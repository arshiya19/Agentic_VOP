import { useState, useMemo } from 'react'
import Topbar from '../components/Topbar'
import Sidebar from '../components/Sidebar'
import MultiSelectFilter from '../components/MultiSelectFilter'
import '../styles/Integrations.css'

// Scanners with a real, wired connector.
// More get added here as we build live connectors for each.
const SCANNERS = [
  { tool: 'osv', label: 'OSV.dev' },
]

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
    apiTool('snyk-appsec', 'Snyk'),
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
                {filteredTools.map(tool => (
                  <div
                    key={tool.id}
                    className="integration-card-modern"
                    onClick={() => setSelectedTool(tool)}
                  >
                    <div className="integration-card-name">
                      {tool.name}
                    </div>

                    {searchTerm && (
                      <div className="integration-category-badge">
                        {tool.category}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </main>
      </div>

      {selectedTool && (
        <div
          className="integration-modal-overlay"
          onClick={() => setSelectedTool(null)}
        >
          <div
            className="integration-modal"
            onClick={(e) => e.stopPropagation()}
          >
            <h2>{selectedTool.name}</h2>
            <p>{selectedTool.description}</p>

            {selectedTool.authType === 'api' && (
              <div className="integration-form">
                {selectedTool.fields?.map(field => (
                  <input
                    key={field.key}
                    type={field.type}
                    placeholder={field.label}
                  />
                ))}
              </div>
            )}

            <div className="integration-modal-actions">
              {selectedTool.authType === 'oauth' && (
                <button className="connect-btn-modern">
                  Connect with OAuth
                </button>
              )}

              <button
                className="integration-close-btn"
                onClick={() => setSelectedTool(null)}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
