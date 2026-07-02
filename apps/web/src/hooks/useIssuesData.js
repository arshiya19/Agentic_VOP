// Issues page data hook — pulls rows from the `issue_with_asset` view (so we
// get the asset join for free) and maps them into the shape the existing
// Issues.jsx UI expects (the 12-column ISSUE_COLUMNS list).
//
// Sort: created_at DESC — newest issues at the top.
// Limit: 500 — covers today's ~404 rows with headroom. Bump to server-side
//        pagination if/when this grows past a few thousand.
// Realtime: subscribe to INSERT/UPDATE on `issues`, debounce 600 ms, re-fetch.

import { useEffect, useState } from 'react'
import { supabase } from '../lib/supabase'

const FETCH_LIMIT = 500

// Maps the issue `source` slug to a security-domain category label.
// These align with the categories shown on the Integrations page.
const SOURCE_TO_TYPE = {
  osv:              'SCA',
  dependabot:      'SCA',
  snyk:            'SCA',
  'snyk-appsec':   'AppSec',
  trivy:           'Cloud Security',
  'trivy-cloud':   'Cloud Security',
  grype:           'Cloud Security',
  tenable:         'VM',
  'tenable-cloud': 'Cloud Security',
  'tenable-nessus-vuln': 'VM',
  qualys:          'VM',
  'qualys-vmdr-vuln': 'VM',
  owasp:           'DAST',
  zap:             'DAST',
  'owasp-zap':     'DAST',
  'owasp-zap-appsec': 'DAST',
  'semgrep-appsec': 'SAST',
  'sonarqube-appsec': 'SAST',
  'checkmarx-appsec': 'SAST',
  'veracode-appsec': 'SAST',
  'burp-suite':    'DAST',
  'crowdstrike-vuln': 'VM',
  'rapid7-vuln':   'VM',
  'aws-inspect-cloud': 'CSPM',
  'aws-securityhub-cloud': 'CSPM',
  'checkov-cspm':  'CSPM',
  'iac-scanning-cloud': 'IaC',
  'paloalto-cloud': 'CSPM',
  'wiz-cloud':     'CSPM',
}

function getIssueType(source) {
  if (!source) return ''
  return SOURCE_TO_TYPE[source] || SOURCE_TO_TYPE[source.toLowerCase()] || ''
}

export function useIssuesData() {
  const [issues, setIssues] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let mounted = true
    let debounceTimer = null

    async function loadAll() {
      const { data, error } = await supabase
        .from('issue_with_asset')
        .select(
          'id, source, cve_id, severity, derived_risk, description, ' +
            'first_detected, cvss_attack_vector, remediation_suggestion, ' +
            'asset_identity, created_at, ' +
            'asset_id, asset_name, asset_type'
        )
        .order('created_at', { ascending: false })
        .limit(FETCH_LIMIT)

      if (!mounted) return
      if (error) {
        // Surface in console so devs see schema/RLS issues; UI just stays empty.
        console.error('useIssuesData fetch error:', error)
        setLoading(false)
        return
      }

      const mapped = (data || []).map((row) => ({
        // Pad the bigint id to a 5-digit "ISS-NNNNN" so the column has a stable shape.
        issue_id: row.id != null ? `ISS-${String(row.id).padStart(5, '0')}` : '',
        // Asset display: prefer the resolved asset name, then fall back to whatever
        // identifier was in asset_identity (hostname, project, or anything).
        asset_id:
          row.asset_name ||
          row.asset_id ||
          row?.asset_identity?.hostname ||
          row?.asset_identity?.project ||
          row?.asset_identity?.repo ||
          row?.asset_identity?.target ||
          '',
        asset_type: getIssueType(row.source),
        cve_id: row.cve_id || '',
        severity: row.severity || '',
        derived_risk: row.derived_risk,
        description: row.description || '',
        // Threat vector ≈ CVSS attack vector (closest field we have today).
        threat_vector: row.cvss_attack_vector || '',
        // Derived: do we have an AI-suggested fix for this finding?
        remediable: row.remediation_suggestion ? 'Yes' : 'No',
        source: row.source || '',
        first_detected: row.first_detected,
        // No CVE-published-date in our schema today — leave blank for now.
        cve_published: '',
      }))

      setIssues(mapped)
      setLoading(false)
    }

    loadAll()

    const channel = supabase
      .channel('issues-page-stream')
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
  }, [])

  return { issues, loading }
}
