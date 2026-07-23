// Assets page data hook — pulls rows from the `assets` table and maps them
// into the shape the existing Assets.jsx UI expects.
//
// Sort: name ASC — alphabetical by default.
// Limit: 500 — covers today's asset count with headroom.
// Realtime: subscribe to INSERT/UPDATE/DELETE on `assets`, debounce 600 ms, re-fetch.

import { useEffect, useState } from 'react'
import { supabase } from '../lib/supabase'

const FETCH_LIMIT = 500

// Map numeric business_criticality (1-5) to display labels.
const CRITICALITY_MAP = {
  5: 'Critical',
  4: 'High',
  3: 'Medium',
  2: 'Low',
  1: 'Info',
}

export function useAssetsData() {
  const [assets, setAssets] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let mounted = true
    let debounceTimer = null

    async function loadAll() {
      const { data, error } = await supabase
        .from('assets')
        .select(
          'asset_id, name, hostname, ip_address, asset_type, environment, ' +
            'business_owner, contact_email, application_name, description, ' +
            'repo_url, exposure, business_criticality, data_classification, ' +
            'compliance_tags, owner_team, network_zone, last_seen_at, ' +
            'created_at, updated_at'
        )
        .order('name', { ascending: true })
        .limit(FETCH_LIMIT)

      if (!mounted) return
      if (error) {
        console.error('useAssetsData fetch error:', error)
        setLoading(false)
        return
      }

      const mapped = (data || []).map((row) => ({
        asset_id: row.asset_id || '',
        type: row.asset_type || '',
        // Display name: prefer hostname, then name, then application_name
        hostname: row.hostname || row.name || row.application_name || '',
        application_name: row.application_name || row.name || '',
        asset_criticality: CRITICALITY_MAP[row.business_criticality] || 'Low',
        business_criticality: row.business_criticality,
        environment: row.environment
          ? row.environment.charAt(0).toUpperCase() + row.environment.slice(1)
          : '',
        it_owner: row.business_owner || row.owner_team || '',
        contact_email: row.contact_email || '',
        data_classification: row.data_classification
          ? row.data_classification.charAt(0).toUpperCase() + row.data_classification.slice(1)
          : '',
        exposure: row.exposure || '',
        network_zone: row.network_zone || '',
        compliance_tags: row.compliance_tags || [],
        description: row.description || '',
        repo_url: row.repo_url || '',
        ip_address: row.ip_address || '',
        last_seen_at: row.last_seen_at,
        name: row.name || '',
      }))

      setAssets(mapped)
      setLoading(false)
    }

    loadAll()

    const channel = supabase
      .channel('assets-page-stream')
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'assets' },
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
  }, [])

  return { assets, loading }
}

/**
 * Fetch issues for a specific asset by asset_id.
 * Uses the issue_with_asset view to get the joined shape.
 */
export async function fetchIssuesForAsset(assetId) {
  const { data, error } = await supabase
    .from('issue_with_asset')
    .select(
      'id, source, cve_id, severity, derived_risk, description, ' +
        'first_detected, cvss_attack_vector, remediation_suggestion, ' +
        'asset_identity, created_at, asset_id, asset_name, asset_type'
    )
    .eq('asset_id', assetId)
    .order('derived_risk', { ascending: false, nullsFirst: false })
    .limit(100)

  if (error) {
    console.error('fetchIssuesForAsset error:', error)
    return []
  }

  return (data || []).map((row) => ({
    issue_id: row.id != null ? `ISS-${String(row.id).padStart(5, '0')}` : '',
    asset_name:
      row.asset_name ||
      row?.asset_identity?.hostname ||
      row?.asset_identity?.project ||
      '',
    asset_type: row.asset_type || '',
    cve_id: row.cve_id || '',
    severity: row.severity || '',
    derived_risk: row.derived_risk,
    description: row.description || '',
    threat_vector: row.cvss_attack_vector || '',
    remediable: row.remediation_suggestion ? 'Yes' : 'No',
    source: row.source || '',
    first_detected: row.first_detected,
  }))
}
