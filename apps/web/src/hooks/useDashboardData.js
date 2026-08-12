// Dashboard data hook — encapsulates the four queries the Dashboard needs
// (stats, latest CVEs, top risk drivers, daily counts) plus a Supabase
// Realtime subscription that re-fetches when issues change.
//
// Refresh strategy: on any INSERT or UPDATE to the `issues` table we
// re-run the four queries, debounced by 600 ms so a batch of inserts
// from one scan only triggers a single refresh.
//
// Validated / Remediated counters are returned as `null` for now —
// the ingestion layer doesn't track those states yet. Components
// should render those as `—` until later phases add the tracking.

import { useEffect, useState } from 'react'
import { supabase } from '../lib/supabase'

const RANGE_TO_DAYS = { '14d': 14, '30d': 30, '90d': 90 }

const SEVERITY_RANK = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 }

// Empty bucket helper for the Exposure Map cards — every card carries the
// same shape so the renderer doesn't need branching.
const emptyExposureBucket = () => ({
  assetCount: 0,
  findingCount: 0,
  critical: 0,
  high: 0,
  medium: 0,
})

export function useDashboardData(chartRange = '14d') {
  const [stats, setStats] = useState({
    total: 0,
    requiringAction: 0,
    readyToRemediate: 0,
    validated: null, // not tracked yet
    remediated: null, // not tracked yet
    severityBreakdown: { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 },
    todayAdded: 0, // issues added today
    previousTotal: 0, // total minus today's additions
  })
  const [latestCves, setLatestCves] = useState([])
  const [topRiskDrivers, setTopRiskDrivers] = useState([])
  const [chartData, setChartData] = useState([])
  const [exposureMap, setExposureMap] = useState({
    // Row 1 — context cards
    internetFacing:   emptyExposureBucket(),
    crownJewel:       emptyExposureBucket(),
    regulatory:       { ...emptyExposureBucket(), tags: [] },
    // Row 2 — threat-zone cards
    zoneInternet:     emptyExposureBucket(),
    zoneExtranet:     emptyExposureBucket(),
    zoneIntranet:     emptyExposureBucket(),
  })
  const [loading, setLoading] = useState(true)
  const [lastUpdatedAt, setLastUpdatedAt] = useState(null)

  useEffect(() => {
    let mounted = true
    let debounceTimer = null

    async function loadAll() {
      // Pull a reasonable slab of recent issues for severity + CVE + chart math.
      // Anything older than chartRange + a little buffer is irrelevant here.
      const days = RANGE_TO_DAYS[chartRange] ?? 14
      const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString()

      const [countRes, severityRes, topRiskRes, recentRes, exposureRes, remPkgRes] = await Promise.all([
        // 1. Total issue count (head=true means we only get the count, no rows)
        supabase.from('issues').select('*', { count: 'exact', head: true }),

        // 2. Severity + remediation breakdown — pull just those columns
        supabase.from('issues').select('severity, remediation_suggestion'),

        // 3. Top 10 by derived_risk (the "Top Risk Drivers" table)
        supabase
          .from('issues')
          .select('id, cve_id, title, severity, derived_risk, asset_identity, source')
          .not('derived_risk', 'is', null)
          .order('derived_risk', { ascending: false })
          .limit(10),

        // 4. Recent rows within the chart range — used for both the CVE ticker
        //    and the per-day count chart
        supabase
          .from('issues')
          .select('id, cve_id, severity, created_at')
          .gte('created_at', since)
          .order('created_at', { ascending: false })
          .limit(2000),

        // 5. Exposure-map: pull issues joined to their asset (via issue_with_asset
        //    view created by migration 0018). Only the columns we need for the
        //    6 cards' rollups.
        supabase
          .from('issue_with_asset')
          .select(
            'severity, asset_id, asset_exposure, asset_business_criticality, ' +
              'asset_compliance_tags, asset_network_zone'
          ),

        // 6. Remediation packages count (awaiting_approval + ready_for_execution)
        supabase
          .from('remediation_packages')
          .select('status, pathways, recommended_pathway_index, created_at, approved_at'),
      ])

      if (!mounted) return

      // ---- stats ----
      const severityBreakdown = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 }
      let requiringAction = 0
      for (const row of severityRes.data || []) {
        if (row.severity && severityBreakdown[row.severity] !== undefined) {
          severityBreakdown[row.severity] += 1
        }
        if (row.severity === 'Critical' || row.severity === 'High') requiringAction += 1
      }
      // Count issues added today
      const todayStr = new Date().toISOString().slice(0, 10)
      let todayAdded = 0
      for (const row of recentRes.data || []) {
        if ((row.created_at || '').slice(0, 10) === todayStr) todayAdded += 1
      }

      // Count remediation packages that are ready
      let readyToRemediate = 0
      let validated = 0
      let confidenceSum = 0
      let confidenceCount = 0
      let remediated = 0
      let mttrSum = 0
      let mttrCount = 0
      if (remPkgRes.data && remPkgRes.data.length > 0) {
        for (const row of remPkgRes.data || []) {
          if (row.status === 'awaiting_approval' || row.status === 'ready_for_execution') {
            readyToRemediate += 1
          }
          if (row.status === 'ready_for_execution') {
            remediated += 1
            // Compute MTTR: time from created_at to approved_at
            if (row.created_at && row.approved_at) {
              const created = new Date(row.created_at)
              const approved = new Date(row.approved_at)
              const diffMs = approved - created
              if (diffMs > 0) {
                mttrSum += diffMs
                mttrCount += 1
              }
            }
          }
          // Check validation status from the recommended pathway
          const pwIdx = row.recommended_pathway_index ?? 0
          const pw = row.pathways?.[pwIdx] || row.pathways?.[0]
          if (pw?.validation_metadata?.status === 'validated') {
            validated += 1
          }
          if (pw?.confidence_score != null) {
            confidenceSum += pw.confidence_score
            confidenceCount += 1
          }
        }
      } else {
        // Fallback: count issues that have an AI-suggested fix
        for (const row of severityRes.data || []) {
          if (row.remediation_suggestion) readyToRemediate += 1
        }
      }

      const total = countRes.count ?? 0
      const avgConfidence = confidenceCount > 0 ? Math.round(confidenceSum / confidenceCount) : null
      // MTTR in days (or hours if < 1 day)
      let avgMttr = null
      if (mttrCount > 0) {
        const avgMs = mttrSum / mttrCount
        const avgDays = avgMs / (1000 * 60 * 60 * 24)
        if (avgDays >= 1) {
          avgMttr = `${Math.round(avgDays)}d`
        } else {
          const avgHours = avgMs / (1000 * 60 * 60)
          avgMttr = `${Math.round(avgHours)}h`
        }
      }
      setStats({
        total,
        requiringAction,
        readyToRemediate,
        validated: validated || null,
        avgConfidence,
        remediated: remediated || null,
        avgMttr,
        severityBreakdown,
        todayAdded,
        previousTotal: total - todayAdded,
      })

      // ---- latest CVEs (dedupe, keep highest severity per CVE) ----
      const cveMap = new Map()
      for (const row of recentRes.data || []) {
        if (!row.cve_id) continue
        const existing = cveMap.get(row.cve_id)
        if (!existing) {
          cveMap.set(row.cve_id, { id: row.cve_id, severity: row.severity, count: 1 })
        } else {
          existing.count += 1
          if (
            (SEVERITY_RANK[row.severity] ?? -1) > (SEVERITY_RANK[existing.severity] ?? -1)
          ) {
            existing.severity = row.severity
          }
        }
      }
      setLatestCves(Array.from(cveMap.values()).slice(0, 20))

      // ---- top risk drivers ----
      setTopRiskDrivers(
        (topRiskRes.data || []).map((row) => ({
          id: row.id,
          cve: row.cve_id || row.source,
          name: row.title || row.cve_id || 'Untitled',
          avg_risk_score: row.derived_risk != null ? Math.round(row.derived_risk) : 0,
          total_affected: 1, // we don't have an asset rollup yet; one issue == one occurrence
          asset_id: row?.asset_identity?.hostname || row?.asset_identity?.target || '',
          criticals: row.severity === 'Critical' ? 1 : 0,
          high: row.severity === 'High' ? 1 : 0,
        }))
      )

      // ---- chart data: bucket recent issues by ISO date string ----
      const bucket = new Map() // 'YYYY-MM-DD' -> count
      for (let d = 0; d < days; d++) {
        const day = new Date(Date.now() - d * 24 * 60 * 60 * 1000).toISOString().slice(0, 10)
        bucket.set(day, 0)
      }
      for (const row of recentRes.data || []) {
        const day = (row.created_at || '').slice(0, 10)
        if (bucket.has(day)) bucket.set(day, bucket.get(day) + 1)
      }
      // Oldest → newest for left-to-right chart reading
      setChartData(
        Array.from(bucket.entries())
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([day, count]) => ({
            day: day.slice(5), // "MM-DD"
            exposure: count,
            remediated: 0, // not tracked yet
            validated: 0, // not tracked yet
          }))
      )

      // ---- Exposure Map: roll up issues joined to their asset ----
      // Each card tracks (assetCount, findingCount, critical, high, medium).
      // Asset counts are sets so duplicates across issues don't double-count.
      const newExposure = {
        internetFacing: emptyExposureBucket(),
        crownJewel:     emptyExposureBucket(),
        regulatory:     { ...emptyExposureBucket(), tags: [] },
        zoneInternet:   emptyExposureBucket(),
        zoneExtranet:   emptyExposureBucket(),
        zoneIntranet:   emptyExposureBucket(),
      }
      const assetSets = {
        internetFacing: new Set(),
        crownJewel:     new Set(),
        regulatory:     new Set(),
        zoneInternet:   new Set(),
        zoneExtranet:   new Set(),
        zoneIntranet:   new Set(),
      }
      const regulatoryAssetsByTag = {} // tag -> Set<asset_id>
      const regulatoryFindingsByTag = {} // tag -> count

      const tally = (bucketKey, row) => {
        newExposure[bucketKey].findingCount += 1
        if (row.severity === 'Critical') newExposure[bucketKey].critical += 1
        else if (row.severity === 'High') newExposure[bucketKey].high += 1
        else if (row.severity === 'Medium') newExposure[bucketKey].medium += 1
        if (row.asset_id) assetSets[bucketKey].add(row.asset_id)
      }

      for (const row of exposureRes.data || []) {
        // Skip rows where the issue didn't attribute to an asset (no card applies).
        if (!row.asset_id) continue

        // ----- Row 1: context cards -----
        if (row.asset_exposure === 'public') tally('internetFacing', row)
        if (
          typeof row.asset_business_criticality === 'number' &&
          row.asset_business_criticality >= 4
        ) {
          tally('crownJewel', row)
        }
        const tags = row.asset_compliance_tags || []
        if (tags.length > 0) {
          tally('regulatory', row)
          for (const tag of tags) {
            if (!regulatoryAssetsByTag[tag]) regulatoryAssetsByTag[tag] = new Set()
            regulatoryAssetsByTag[tag].add(row.asset_id)
            regulatoryFindingsByTag[tag] = (regulatoryFindingsByTag[tag] || 0) + 1
          }
        }

        // ----- Row 2: threat-zone cards -----
        if (row.asset_network_zone === 'internet') tally('zoneInternet', row)
        else if (row.asset_network_zone === 'extranet') tally('zoneExtranet', row)
        else if (row.asset_network_zone === 'intranet') tally('zoneIntranet', row)
      }

      for (const key of Object.keys(assetSets)) {
        newExposure[key].assetCount = assetSets[key].size
      }
      // Regulatory card carries a per-tag breakdown for the chip list.
      newExposure.regulatory.tags = Object.keys(regulatoryAssetsByTag)
        .sort()
        .map((tag) => ({
          tag,
          assets: regulatoryAssetsByTag[tag].size,
          findings: regulatoryFindingsByTag[tag] || 0,
        }))
      setExposureMap(newExposure)

      setLastUpdatedAt(new Date())
      setLoading(false)
    }

    loadAll()

    // Realtime: any change to `issues` triggers a debounced re-fetch.
    // Debouncing collapses a burst of inserts (one scan = many rows at once)
    // into a single recompute.
    const channel = supabase
      .channel('dashboard-issues-stream')
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'issues' },
        () => {
          if (debounceTimer) clearTimeout(debounceTimer)
          debounceTimer = setTimeout(() => {
            if (mounted) loadAll()
          }, 600)
        }
      )
      .subscribe()

    return () => {
      mounted = false
      if (debounceTimer) clearTimeout(debounceTimer)
      supabase.removeChannel(channel)
    }
  }, [chartRange])

  return {
    stats,
    latestCves,
    topRiskDrivers,
    chartData,
    exposureMap,
    loading,
    lastUpdatedAt,
  }
}
