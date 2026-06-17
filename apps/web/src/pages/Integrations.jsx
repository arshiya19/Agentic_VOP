import { useState, useMemo, useEffect, useCallback } from 'react'
import Topbar from '../components/Topbar'
import Sidebar from '../components/Sidebar'
import MultiSelectFilter from '../components/MultiSelectFilter'
import ScannerEndpointModal from '../components/ScannerEndpointModal'
import '../styles/Integrations.css'
import '../styles/AgentModelConfig.css' // reuse .amc-banner-* helpers

// Built-in scanners that always show in "Run a scan" even before any
// custom registration. Anything else added by the user via the modal
// appears here dynamically (driven by /admin/scanners).
const BUILTIN_SCANNERS = [
  { tool: 'osv', label: 'OSV.dev' },
]

// Catalog cards use namespaced IDs (e.g. "owasp-zap-appsec") but some
// scanners are registered under shorter slugs in connection_registry
// (e.g. "zap"). This map lets the "configured" dot light up for those
// scanners too without forcing a DB rename.
//   key   = catalog id (tool.id in INTEGRATION_CATALOG)
//   value = array of slugs that should also count as "this is configured"
const CATALOG_ID_ALIASES = {
  'owasp-zap-appsec': ['zap', 'owasp-zap'],
  'github-dependabot-appsec': ['dependabot', 'github-dependabot'],
}

const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

const apiTool = (id, name) => ({
  id,
  name,
  description: `Integrate ${name} to ingest findings and automate workflows.`,
  authType: 'api',
  status: 'disconnected',
  fields: [
    { key: 'apiKey', label: 'API Key', type: 'text' },
    { key: 'secret', label: 'Secret', type: 'password' },
  ],
})

const oauthTool = (id, name) => ({
  id,
  name,
  description: `Connect ${name} using secure OAuth authentication.`,
  authType: 'oauth',
  status: 'disconnected',
  fields: [],
})

const INTEGRATION_CATALOG = [
  { category: 'Application Security', tools: [
    apiTool('checkmarx-appsec', 'Checkmarx'),
    oauthTool('github-dependabot-appsec', 'Github Dependabot'),
    oauthTool('hackerone-appsec', 'Hackerone'),
    apiTool('owasp-zap-appsec', 'OWASP ZAP'),
    apiTool('semgrep-appsec', 'Semgrep'),
    apiTool('snyk-appsec', 'Snyk'),
    apiTool('sonarqube-appsec', 'SonarQube'),
    apiTool('veracode-appsec', 'Veracode'),
  ]},
  { category: 'Asset Management', tools: [
    oauthTool('aws-asset', 'AWS'),
    oauthTool('jira-asset', 'JIRA'),
    apiTool('jupiterone-asset', 'JupiterOne'),
    oauthTool('oci-asset', 'OCI'),
    apiTool('servicenow-cmdb-asset', 'ServiceNow CMDB'),
  ]},
  { category: 'Cloud Security', tools: [
    apiTool('aws-inspect-cloud', 'AWS Inspect'),
    apiTool('aws-securityhub-cloud', 'AWS Security Hub (CSPM)'),
    apiTool('crowdstrike-cloud', 'HorizonCSPM (Crowdstrike)'),
    apiTool('iac-scanning-cloud', 'Checkov (IaC Scanning)'),
    apiTool('paloalto-cloud', 'Prisma Cloud (Palo Alto)'),
    apiTool('tenable-cloud', 'Tenable Cloud Security'),
    apiTool('trivy-cloud', 'Trivy'),
    apiTool('wiz-cloud', 'Wiz'),
  ]},
  { category: 'DSPM / DLP', tools: [
    apiTool('cyera-dspm', 'Cyera'),
    apiTool('sentra-dspm', 'Sentra'),
    apiTool('symmetry-dspm', 'Symmetry'),
    apiTool('veronous-dspm', 'Varonis'),
  ]},
  { category: 'External Attack Surface Management', tools: [
    apiTool('crowdstrike-easm', 'Falcon Surface (Crowdstrike)'),
    apiTool('cycognito-easm', 'CyCognito'),
    apiTool('microsoft-defender-easm', 'Microsoft Defender'),
  ]},
  { category: 'Non-human Identity', tools: [
    apiTool('entro-nhi', 'Entro Security'),
    apiTool('hush-nhi', 'Hush Security'),
  ]},
  { category: 'Pentest', tools: [
    apiTool('horizon3-pentest', 'Horizon3.ai'),
    apiTool('inspect-pentest', 'Inspective'),
  ]},
  { category: 'SAAS Security', tools: [
    apiTool('appomni-saas', 'AppOmni'),
    apiTool('casb-saas', 'CASB'),
    apiTool('obsidian-saas', 'Obsidian'),
    apiTool('valence-saas', 'Valence'),
  ]},
  { category: 'Security Controls', tools: [
    apiTool('armis-controls', 'Armis'),
    apiTool('safebreach-controls', 'SafeBreach'),
  ]},
  { category: 'Threat Feed', tools: [
    apiTool('cisa-kev-threat', 'CISA KEV'),
    apiTool('epss-threat', 'EPSS'),
    apiTool('euvd-threat', 'EUVD'),
    apiTool('google-ti-threat', 'Google Threat Intelligence'),
    apiTool('mitre-threat', 'MITRE'),
    apiTool('nvd-threat', 'NVD'),
  ]},
  { category: 'Ticketing', tools: [
    oauthTool('azuredevops-ticket', 'Azure DevOps'),
    oauthTool('jira-ticket', 'JIRA'),
    oauthTool('monday-ticket', 'Monday'),
    oauthTool('servicenow-ticket', 'Service Now'),
    oauthTool('slack-ticket', 'Slack'),
    oauthTool('teams-ticket', 'Teams'),
  ]},
  { category: 'Training and Compliance', tools: [
    apiTool('abnormal-training', 'Abnormal'),
    apiTool('adaptive-training', 'Adaptive'),
    apiTool('bugbounty-training', 'Bug Bounty'),
    apiTool('bugcrowd-training', 'Bug Crowd'),
    oauthTool('hackerone-training', 'HackerOne'),
    apiTool('inspective-training', 'Inspective'),
    apiTool('knowbefore-training', 'Knowbe4'),
  ]},
  { category: 'Vulnerability Management', tools: [
    apiTool('crowdstrike-vuln', 'Crowdstrike'),
    apiTool('paloalto-vuln', 'Palo Alto'),
    apiTool('rapid7-vuln', 'Rapid7 InsiteVM'),
    apiTool('tenable-nessus-vuln', 'Tenable Nessus'),
  ]},
]

export default function Integrations() {
  const [activeCategory, setActiveCategory] = useState('All')
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedCategories, setSelectedCategories] = useState([])
  const [isFilterOpen, setIsFilterOpen] = useState(false)
  const [selectedTool, setSelectedTool] = useState(null)
  const [integrationsData] = useState(INTEGRATION_CATALOG)

  // Scanner runner panel state
  const [selectedScanners, setSelectedScanners] = useState(new Set())
  const [isTriggering, setIsTriggering] = useState(false)
  const [lastResult, setLastResult] = useState(null)

  // Registered scanners (from /admin/scanners). Used to:
  //  - Show a "configured" dot on integration cards.
  //  - Build the dynamic SCANNERS list in the Run-a-scan card.
  //  - Decide whether the modal renders in "create" or "edit" mode.
  const [registeredScanners, setRegisteredScanners] = useState([])

  // Page-level success toast — surfaced after the modal saves and closes.
  const [toast, setToast] = useState(null)

  useEffect(() => {
    if (!toast) return
    const t = setTimeout(() => setToast(null), 3500)
    return () => clearTimeout(t)
  }, [toast])

  const refreshRegisteredScanners = useCallback(async () => {
    try {
      const res = await fetch(`${API_URL}/admin/scanners`)
      if (!res.ok) return
      const data = await res.json()
      setRegisteredScanners(data.scanners || [])
    } catch {
      // Backend may not be up yet on first paint — fail silently and the
      // BUILTIN_SCANNERS fallback keeps the page functional.
    }
  }, [])

  useEffect(() => {
    refreshRegisteredScanners()
  }, [refreshRegisteredScanners])

  // Merge built-ins with the registered set (registered wins on tool collision).
  // Label resolution: prefer catalog's display name when the slug matches a
  // catalog entry, otherwise fall back to the raw tool slug.
  const SCANNERS = useMemo(() => {
    const catalogNameById = new Map()
    for (const group of INTEGRATION_CATALOG) {
      for (const tool of group.tools) catalogNameById.set(tool.id, tool.name)
    }
    const map = new Map(BUILTIN_SCANNERS.map((s) => [s.tool, s]))
    for (const s of registeredScanners) {
      if (s.enabled) {
        map.set(s.tool, {
          tool: s.tool,
          label: catalogNameById.get(s.tool) || s.tool,
        })
      }
    }
    return Array.from(map.values())
  }, [registeredScanners])

  const registeredByTool = useMemo(() => {
    const m = new Map()
    for (const s of registeredScanners) m.set(s.tool, s)
    return m
  }, [registeredScanners])

  const toggleScanner = (tool) => {
    setSelectedScanners((prev) => {
      const next = new Set(prev)
      if (next.has(tool)) next.delete(tool)
      else next.add(tool)
      return next
    })
  }

  const selectAllScanners = () => {
    setSelectedScanners((prev) =>
      prev.size === SCANNERS.length ? new Set() : new Set(SCANNERS.map((s) => s.tool))
    )
  }

  const handleTrigger = async () => {
    if (selectedScanners.size === 0 || isTriggering) return
    setIsTriggering(true)
    setLastResult(null)

    const eventId = `EVT-UI-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
    try {
      const res = await fetch(`${API_URL}/agents/trigger`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          event_id: eventId,
          action: 'FETCH',
          targets: { scanners: Array.from(selectedScanners) },
        }),
      })
      if (!res.ok) {
        const text = await res.text()
        throw new Error(`HTTP ${res.status}: ${text.slice(0, 200)}`)
      }
      const data = await res.json()
      setLastResult({
        ok: true,
        message: `Run triggered (${data.event_id}) — status ${data.status}. Open the Agents page to watch progress.`,
      })
      // Keep the button disabled for an extra 5 seconds after a successful
      // trigger so rapid follow-up clicks can't create duplicate runs.
      setTimeout(() => setIsTriggering(false), 5000)
      return
    } catch (err) {
      setLastResult({ ok: false, message: `Failed to trigger: ${err.message}` })
    }
    setIsTriggering(false)
  }

  const allTools = useMemo(() => {
    return integrationsData.flatMap(group =>
      group.tools.map(tool => ({
        ...tool,
        category: group.category
      }))
    )
  }, [integrationsData])

  const filteredTools = useMemo(() => {
    let base =
      activeCategory === 'All'
        ? allTools
        : integrationsData
          .find(group => group.category === activeCategory)
          ?.tools.map(tool => ({
            ...tool,
            category: activeCategory
          })) || []

    if (activeCategory === 'All' && selectedCategories.length > 0) {
      base = base.filter(tool =>
        selectedCategories.includes(tool.category)
      )
    }

    base = base.filter(tool =>
      tool.name.toLowerCase().includes(searchTerm.toLowerCase())
    )

    return base
  }, [activeCategory, searchTerm, selectedCategories, allTools, integrationsData])

  const categoryOptions = useMemo(() => {
    return integrationsData.map(group => ({
      key: group.category,
      label: group.category,
      count: group.tools.length
    }))
  }, [integrationsData])

  return (
    <>
      <Topbar />
      <div className="app-layout">
        <Sidebar />

        <main className="integrations-page">
          <div className="integrations-header">
            <h1>Integrations</h1>
            <p className="integrations-subtitle">
              Connect with security, compliance, and infrastructure tools
            </p>
          </div>

          <section className="scanner-runner">
            <div className="scanner-runner-header">
              <div>
                <h2>Run a scan</h2>
                <p className="scanner-runner-sub">
                  Select one or more scanners and trigger a normalization run.
                </p>
              </div>
              <button
                type="button"
                className="scanner-runner-link"
                onClick={selectAllScanners}
              >
                {selectedScanners.size === SCANNERS.length ? 'Clear all' : 'Select all'}
              </button>
            </div>

            <div className="scanner-runner-cards">
              {SCANNERS.map((s) => {
                const selected = selectedScanners.has(s.tool)
                return (
                  <button
                    key={s.tool}
                    type="button"
                    className={`scanner-card ${selected ? 'selected' : ''}`}
                    onClick={() => toggleScanner(s.tool)}
                    disabled={isTriggering}
                  >
                    <span className={`scanner-card-check ${selected ? 'checked' : ''}`}>
                      {selected && (
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
                          <polyline points="20 6 9 17 4 12"></polyline>
                        </svg>
                      )}
                    </span>
                    <span className="scanner-card-label">{s.label}</span>
                    <span className="scanner-card-tool">{s.tool}</span>
                  </button>
                )
              })}
            </div>

            <div className="scanner-runner-actions">
              <button
                type="button"
                className="scanner-runner-btn"
                onClick={handleTrigger}
                disabled={selectedScanners.size === 0 || isTriggering}
              >
                {isTriggering
                  ? 'Triggering…'
                  : `Fetch findings${selectedScanners.size ? ` (${selectedScanners.size})` : ''}`}
              </button>
              {lastResult && (
                <div
                  className={`scanner-runner-result ${
                    lastResult.ok ? 'success' : 'error'
                  }`}
                >
                  {lastResult.message}
                </div>
              )}
            </div>
          </section>

          <div className="integrations-layout">
            <div className={`integrations-categories ${isFilterOpen ? 'no-scroll' : ''}`}>

              <div className="category-all-row">
                <button
                  className={`category-tab category-tab-all ${activeCategory === 'All' ? 'active' : ''}`}
                  onClick={() => setActiveCategory('All')}
                >
                  <span>All Integrations</span>
                  <span className="category-count">
                    {allTools.length}
                  </span>
                </button>

                <MultiSelectFilter
                  title="Categories"
                  options={categoryOptions}
                  value={selectedCategories}
                  onChange={setSelectedCategories}
                  onOpenChange={setIsFilterOpen}
                />
              </div>

              {integrationsData
                .filter(group =>
                  selectedCategories.length === 0 ||
                  selectedCategories.includes(group.category)
                )
                .map(group => (
                  <button
                    key={group.category}
                    className={`category-tab ${activeCategory === group.category ? 'active' : ''}`}
                    onClick={() => setActiveCategory(group.category)}
                  >
                    <span>{group.category}</span>
                    <span className="category-count">
                      {group.tools.length}
                    </span>
                  </button>
                ))}
            </div>

            <div className="integrations-content-modern">

              <div className="integrations-search-modern">
                <div className="search-input-wrapper">
                  <input
                    type="text"
                    placeholder="Search tools..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                  />

                  {searchTerm && (
                    <button
                      type="button"
                      className="search-clear-btn"
                      onClick={() => setSearchTerm('')}
                    >
                      <svg
                        width="14"
                        height="14"
                        viewBox="0 0 24 24"
                        stroke="currentColor"
                        fill="none"
                        strokeWidth="2"
                      >
                        <line x1="18" y1="6" x2="6" y2="18" />
                        <line x1="6" y1="6" x2="18" y2="18" />
                      </svg>
                    </button>
                  )}
                </div>
              </div>

              <div className="integration-grid-modern">
                {filteredTools.map(tool => {
                  const aliases = CATALOG_ID_ALIASES[tool.id] || []
                  const configured =
                    registeredByTool.has(tool.id) ||
                    aliases.some((slug) => registeredByTool.has(slug))
                  return (
                    <div
                      key={tool.id}
                      className="integration-card-modern"
                      onClick={() => setSelectedTool(tool)}
                      style={{ position: 'relative' }}
                    >
                      {configured && (
                        <span
                          className="integration-configured-dot"
                          title="Endpoint configured"
                        />
                      )}
                      <div className="integration-card-name">
                        {tool.name}
                      </div>

                      {searchTerm && (
                        <div className="integration-category-badge">
                          {tool.category}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          </div>
        </main>
      </div>

      {selectedTool && (
        <ScannerEndpointModal
          tool={selectedTool}
          existing={registeredByTool.get(selectedTool.id) || null}
          onClose={() => setSelectedTool(null)}
          onSaved={(message) => {
            setToast({ kind: 'ok', message })
            refreshRegisteredScanners()
          }}
        />
      )}

      {toast && (
        <div className={`integrations-toast integrations-toast-${toast.kind}`} role="status">
          <span className="integrations-toast-icon" aria-hidden>
            {toast.kind === 'ok' ? '✓' : '!'}
          </span>
          <span>{toast.message}</span>
          <button
            className="integrations-toast-close"
            onClick={() => setToast(null)}
            aria-label="Dismiss"
          >
            ×
          </button>
        </div>
      )}
    </>
  )
}
