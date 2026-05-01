import { useState, useCallback } from 'react'
import Topbar from '../components/Topbar'
import Sidebar from '../components/Sidebar'
import ColumnToggle, { useColumnVisibility } from '../components/ColumnToggle'
import '../styles/Remediation.css'
import SeverityFilter from '../components/SeverityFilter'
import ViewToggleEyeDropdown from '../components/ViewToggleEye'

const remediationColumns = [
  { key: 'issue_id', label: 'Issue ID' },
  { key: 'scanner_response', label: 'Issue' },
  { key: 'asset_id', label: 'Asset ID' },
  { key: 'asset_type', label: 'Asset Type' },
  { key: 'asset_name', label: 'Asset Name' },
  { key: 'severity', label: 'Severity' },
  { key: 'sla', label: 'SLA Status' },
  { key: 'remediation', label: 'Remediation' },
  { key: 'change_type', label: 'Change Type' },
  { key: 'pathway', label: 'Pathway' },
  { key: 'action', label: 'Action' },
]

// Per-issue evidence keyed by issue_id. Empty until populated by API/agent output.
const evidenceData = {}

// Empty fallback when an issue has no evidence wired in yet.
const getDefaultEvidence = () => ({ steps: [], evidence: '' })

const getSeverityColor = (severity) => {
  const sev = severity?.toUpperCase()
  if (sev === 'CRITICAL') return '#EF4444'
  if (sev === 'HIGH') return '#F97316'
  if (sev === 'MEDIUM') return '#EAB308'
  return '#10B981'
}

const getComplexityColor = (complexity) => {
  const comp = complexity?.toLowerCase()
  if (comp === 'complex') return '#EF4444'
  if (comp === 'medium') return '#F59E0B'
  return '#10B981'
}

const SLA_DAYS = { CRITICAL: 7, HIGH: 15, MEDIUM: 30, LOW: 90 }

const calculateSLA = (dateFound, severity) => {
  if (!dateFound || !severity) return null
  const found = new Date(dateFound)
  const today = new Date()
  const daysSinceFound = Math.floor((today - found) / (1000 * 60 * 60 * 24))
  const slaLimit = SLA_DAYS[severity.toUpperCase()] || 90
  const remaining = slaLimit - daysSinceFound
  return {
    daysSinceFound,
    remaining: Math.abs(remaining),
    breached: remaining < 0,
    label: remaining < 0
      ? `SLA Breached (${Math.abs(remaining)}d)`
      : `Within SLA (${remaining}d)`
  }
}

function SLABadge({ dateFound, severity }) {
  const sla = calculateSLA(dateFound, severity)
  if (!sla) return null
  return (
    <span className={`sla-badge ${sla.breached ? 'breached' : 'within'}`}>
      {sla.label}
    </span>
  )
}

function DiffPanel({ lines, startLine, side }) {
  return (
    <div className="code-diff-panel">
      <div className="code-diff-panel-header">{side === 'left' ? 'Current' : 'Proposed Fix'}</div>
      {lines.map((line, i) => (
        <div key={i} className={`diff-line ${line.type}`}>
          <span className="diff-line-number">{startLine + i}</span>
          <span className="diff-line-content">
            {line.type === 'removed' ? '- ' : line.type === 'added' ? '+ ' : '  '}{line.content}
          </span>
        </div>
      ))}
    </div>
  )
}

function CodeDiffView({ codeDiff, onExpand }) {
  if (!codeDiff) return null

  const removedLines = codeDiff.hunks.flatMap(h =>
    h.lines.filter(l => l.type === 'context' || l.type === 'removed')
  )
  const addedLines = codeDiff.hunks.flatMap(h =>
    h.lines.filter(l => l.type === 'context' || l.type === 'added')
  )
  const startLine = codeDiff.hunks[0]?.oldStart || 1

  return (
    <div className="code-diff-container">
      <div className="code-diff-header">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
          <polyline points="14 2 14 8 20 8"></polyline>
        </svg>
        <span>{codeDiff.fileName}</span>
        <button className="diff-expand-btn" onClick={onExpand} title="Expand code diff">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <polyline points="15 3 21 3 21 9"></polyline>
            <polyline points="9 21 3 21 3 15"></polyline>
            <line x1="21" y1="3" x2="14" y2="10"></line>
            <line x1="3" y1="21" x2="10" y2="14"></line>
          </svg>
        </button>
      </div>
      <div className="code-diff-body">
        <DiffPanel lines={removedLines} startLine={startLine} side="left" />
        <DiffPanel lines={addedLines} startLine={startLine} side="right" />
      </div>
    </div>
  )
}

function CodeDiffModal({ codeDiff, onClose }) {
  if (!codeDiff) return null

  const expandedHunks = codeDiff.expandedHunks || codeDiff.hunks
  const removedLines = expandedHunks.flatMap(h =>
    h.lines.filter(l => l.type === 'context' || l.type === 'removed')
  )
  const addedLines = expandedHunks.flatMap(h =>
    h.lines.filter(l => l.type === 'context' || l.type === 'added')
  )
  const startLine = expandedHunks[0]?.oldStart || 1

  return (
    <div className="diff-modal-overlay" onClick={onClose}>
      <div className="diff-modal-card" onClick={(e) => e.stopPropagation()}>
        <div className="diff-modal-header">
          <div className="diff-modal-title">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
              <polyline points="14 2 14 8 20 8"></polyline>
            </svg>
            <span>Code Changes — {codeDiff.fileName}</span>
          </div>
          <button className="diff-modal-close" onClick={onClose}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="18" y1="6" x2="6" y2="18"></line>
              <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
          </button>
        </div>
        <div className="diff-modal-body">
          <DiffPanel lines={removedLines} startLine={startLine} side="left" />
          <DiffPanel lines={addedLines} startLine={startLine} side="right" />
        </div>
      </div>
    </div>
  )
}

function ChangeDetailView({ changeDetail }) {
  const [expanded, setExpanded] = useState(false)

  if (!changeDetail) return null

  const typeIcon = {
    UPGRADE: (<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="17 1 21 5 17 9"></polyline><path d="M3 11V9a4 4 0 0 1 4-4h14"></path><polyline points="7 23 3 19 7 15"></polyline><path d="M21 13v2a4 4 0 0 1-4 4H3"></path></svg>),
    CONFIG: (<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>),
    ACCESS_CONTROL: (<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>),
    IAM: (<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>),
  }

  return (
    <div className={`code-diff-container ${expanded ? 'expanded' : ''}`}>
      <div className="code-diff-header">
        {typeIcon[changeDetail.type] || typeIcon.CONFIG}
        <span>{changeDetail.title}</span>
        <button className="diff-expand-btn" onClick={() => setExpanded(!expanded)} title={expanded ? 'Collapse' : 'Expand'}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            {expanded ? (
              <>
                <polyline points="4 14 10 14 10 20"></polyline>
                <polyline points="20 10 14 10 14 4"></polyline>
                <line x1="14" y1="10" x2="21" y2="3"></line>
                <line x1="3" y1="21" x2="10" y2="14"></line>
              </>
            ) : (
              <>
                <polyline points="15 3 21 3 21 9"></polyline>
                <polyline points="9 21 3 21 3 15"></polyline>
                <line x1="21" y1="3" x2="14" y2="10"></line>
                <line x1="3" y1="21" x2="10" y2="14"></line>
              </>
            )}
          </svg>
        </button>
      </div>
      <div className="change-detail-body">
        <table className="change-detail-table">
          <thead>
            <tr>
              <th>Setting</th>
              <th>Before</th>
              <th>After</th>
            </tr>
          </thead>
          <tbody>
            {changeDetail.items.map((item, i) => (
              <tr key={i}>
                <td className="change-label">{item.label}</td>
                <td className="change-before">{item.before}</td>
                <td className="change-after">{item.after}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function RemediationDetailCard({ isOpen, onClose, item }) {
  const [activePath, setActivePath] = useState(0)
  const [copied, setCopied] = useState(false)
  const [diffModalOpen, setDiffModalOpen] = useState(false)

  const handleCopy = useCallback((text) => {
    navigator.clipboard.writeText(text).catch(() => {})
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }, [])

  if (!isOpen || !item) return null

  const evidence = evidenceData[item.issue_id] || getDefaultEvidence()
  const paths = evidence.paths || [{ id: 1, name: 'Direct Fix', coverage: '100%', steps: evidence.steps }]
  const currentPath = paths[activePath] || paths[0]
  // Per-path evidence/diff with fallback to top-level
  const activeEvidence = currentPath.evidence || evidence.evidence
  const activeCodeDiff = currentPath.codeDiff || evidence.codeDiff
  const activeChangeDetail = currentPath.changeDetail || evidence.changeDetail
  const showDiff = item.change_type === 'CODE_CHANGE' && activeCodeDiff

  const formatDate = (d) => {
    if (!d) return '—'
    return new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
  }

  return (
    <div className="remediation-detail-overlay" onClick={onClose}>
      <div className="remediation-detail-card horizontal" onClick={(e) => e.stopPropagation()}>
        {/* Left Section */}
        <div className="detail-card-left">
          <div className="detail-card-header">
            <div className="detail-issue-info">
              <span className="detail-issue-id">{item.issue_id}</span>
              <span className={`detail-severity ${item.severity?.toLowerCase()}`}>
                Severity: {item.severity}
              </span>
            </div>
            <SLABadge dateFound={item.date_found} severity={item.severity} />
          </div>

          <div className="detail-meta-grid">
            <div className="detail-meta-item">
              <span className="meta-label">Issue</span>
              <span className="meta-value">{item.scanner_response}</span>
            </div>
            <div className="detail-meta-item">
              <span className="meta-label">Remediation</span>
              <span className="meta-value">{item.remediation}</span>
            </div>
            <div className="detail-meta-row">
              <div className="detail-meta-item">
                <span className="meta-label">Change Type</span>
                <span className="meta-value change-type">{item.change_type}</span>
              </div>
              <div className="detail-meta-item">
                <span className="meta-label">Asset Name</span>
                <span className="meta-value change-type">{item.asset_name}</span>
              </div>
            </div>
            <div className="detail-meta-row">
              <div className="detail-meta-item">
                <span className="meta-label">Date Found</span>
                <span className="meta-value">{formatDate(item.date_found)}</span>
              </div>
              <div className="detail-meta-item">
                <span className="meta-label">First Detected</span>
                <span className="meta-value">{formatDate(item.first_detected)}</span>
              </div>
            </div>
          </div>

          {/* Code Diff for CODE_CHANGE, Change Detail for others */}
          {showDiff ? (
            <CodeDiffView codeDiff={activeCodeDiff} onExpand={() => setDiffModalOpen(true)} />
          ) : activeChangeDetail ? (
            <ChangeDetailView changeDetail={activeChangeDetail} />
          ) : null}

          {/* Evidence Section */}
          <div className="detail-evidence-section">
            <div className="evidence-header">
              <div className="evidence-header-row">
                <div className="evidence-header-left">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                    <polyline points="14 2 14 8 20 8"></polyline>
                    <line x1="16" y1="13" x2="8" y2="13"></line>
                    <line x1="16" y1="17" x2="8" y2="17"></line>
                  </svg>
                  <span>Evidence</span>
                </div>
                <button
                  className={`evidence-copy-btn ${copied ? 'copied' : ''}`}
                  onClick={() => handleCopy(activeEvidence)}
                  title="Copy to clipboard"
                >
                  {copied ? (
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <polyline points="20 6 9 17 4 12"></polyline>
                    </svg>
                  ) : (
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                    </svg>
                  )}
                </button>
              </div>
            </div>
            <div className="evidence-content">
              <pre className="evidence-code">{activeEvidence}</pre>
            </div>
          </div>
        </div>

        {/* Right Section */}
        <div className="detail-card-right">
          {/* Path Tabs */}
          {paths.length > 1 && (
            <div className="path-tabs-container">
              <div className="path-tabs-row">
                {paths.map((path, idx) => (
                  <button
                    key={path.id}
                    className={`path-tab ${activePath === idx ? 'active' : ''}`}
                    onClick={() => setActivePath(idx)}
                  >
                    {path.name}
                  </button>
                ))}
              </div>
              <div className={`path-coverage ${currentPath.coverage === '100%' ? 'full' : 'partial'}`}>
                {currentPath.coverage === '100%'
                  ? `Fixes 100% — ${currentPath.description}`
                  : `Mitigates ${currentPath.coverage} — ${currentPath.description}`}
              </div>
            </div>
          )}

          <div className="upgrade-steps-section">
            <h4>
              Upgrade Steps
              <button className="detail-close-btn" onClick={onClose}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18"></line>
                  <line x1="6" y1="6" x2="18" y2="18"></line>
                </svg>
              </button>
            </h4>
            <div className="upgrade-steps-list">
              {currentPath.steps.map((step, index) => (
                <div key={index} className="upgrade-step-item">
                  <div className="step-number">{index + 1}</div>
                  <div className="step-content">
                    <div className="step-version-row">
                      <span className="version-tag">v{step.version}</span>
                      <span className="step-time-inline">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <circle cx="12" cy="12" r="10"></circle>
                          <polyline points="12 6 12 12 16 14"></polyline>
                        </svg>
                        {step.time}
                      </span>
                    </div>
                    <div className="step-action">{step.action}</div>
                    <div className="step-meta-row-inline">
                      <div className="step-meta-inline-item">
                        <span className="step-meta-label">Severity</span>
                        <span className="step-severity-tag" style={{ background: `${getSeverityColor(step.targetSeverity)}20`, color: getSeverityColor(step.targetSeverity), borderColor: `${getSeverityColor(step.targetSeverity)}40` }}>
                          <span className="severity-arrow">↓</span> {step.targetSeverity}
                        </span>
                      </div>
                      <div className="step-meta-inline-item">
                        <span className="step-meta-label">Complexity</span>
                        <span className="step-complexity-tag" style={{ background: `${getComplexityColor(step.complexity)}20`, color: getComplexityColor(step.complexity), borderColor: `${getComplexityColor(step.complexity)}40` }}>
                          {step.complexity}
                        </span>
                      </div>
                      <div className="step-meta-inline-item">
                        <span className="step-meta-label">Status</span>
                        <span className={`step-validated-tag ${step.validated ? 'validated' : 'not-validated'}`}>
                          {step.validated ? (
                            <><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><polyline points="20 6 9 17 4 12"></polyline></svg> Validated</>
                          ) : (
                            <><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg> Not Validated</>
                          )}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="detail-card-actions">
            <button className="action-btn secondary" onClick={onClose}>Cancel</button>
            <button className="action-btn primary create-pr-btn">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="18" cy="18" r="3"></circle>
                <circle cx="6" cy="6" r="3"></circle>
                <path d="M13 6h3a2 2 0 0 1 2 2v7"></path>
                <line x1="6" y1="9" x2="6" y2="21"></line>
              </svg>
              Create PR
            </button>
          </div>
        </div>
      </div>

      {/* Code Diff Expanded Modal */}
      {diffModalOpen && showDiff && (
        <CodeDiffModal codeDiff={activeCodeDiff} onClose={() => setDiffModalOpen(false)} />
      )}
    </div>
  )
}

// Get highest complexity from upgrade steps
const getHighestComplexity = (item) => {
  const evidence = evidenceData[item.issue_id] || getDefaultEvidence()
  const steps = evidence.steps || []

  // Priority: Complex > Medium > Easy
  let hasComplex = false
  let hasMedium = false

  for (const step of steps) {
    const comp = step.complexity?.toLowerCase()
    if (comp === 'complex') hasComplex = true
    if (comp === 'medium') hasMedium = true
  }

  if (hasComplex) return { d: 'C', label: 'Complex', color: '#EF4444' }
  if (hasMedium) return { d: 'M', label: 'Medium', color: '#F59E0B' }
  return { d: 'E', label: 'Easy', color: '#10B981' }
}

// Pathway Badge Component (E, M, C) - based on highest complexity in steps
function PathwayBadge({ item }) {
  const diff = getHighestComplexity(item)

  return (
    <div className="pathway-with-badge">
      <span className="pathway-text">{item.pathway}</span>
      <span
        className="pathway-badge-small"
        style={{
          background: `${diff.color}20`,
          borderColor: `${diff.color}40`,
          color: diff.color
        }}
        title={`${diff.label} Path`}
      >
        {diff.d}
      </span>
    </div>
  )
}

// Get highest-risk pathway for an asset (based on severity priority)
const getHighestRiskPathway = (issues) => {
  if (!issues || issues.length === 0) return { pathway: '—', severity: null }

  // Severity priority: CRITICAL > HIGH > MEDIUM > LOW
  const severityOrder = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 }

  // Sort issues by severity (highest first)
  const sorted = [...issues].sort((a, b) => {
    const sevA = severityOrder[a.severity?.toUpperCase()] || 0
    const sevB = severityOrder[b.severity?.toUpperCase()] || 0
    return sevB - sevA
  })

  // Return the pathway from the highest severity issue
  return {
    pathway: sorted[0].pathway,
    severity: sorted[0].severity
  }
}

export default function Remediation() {
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedSeverity, setSelectedSeverity] = useState([])
  const [currentPage, setCurrentPage] = useState(1)
  const [selectedItem, setSelectedItem] = useState(null)
  const [detailOpen, setDetailOpen] = useState(false)
  const [selectedAsset, setSelectedAsset] = useState(null)
  const [selectedIssueInPanel, setSelectedIssueInPanel] = useState(null)
  const itemsPerPage = 10
  const [viewMode, setViewMode] = useState('issue')
  const [remediationsData] = useState([])
  const [assetsData] = useState([])

  const remediations = remediationsData

  const assetInfoMap = assetsData.reduce((acc, asset) => {
    acc[asset.asset_id] = {
      asset_type: asset.asset_type,
      asset_name: asset.asset_name
    }
    return acc
  }, {})

  const { visibleColumns, setVisibleColumns, isVisible } = useColumnVisibility(remediations, [], [])

  const filteredRemediations = remediations.filter(item => {
    const matchesFilter = selectedSeverity.length === 0 || selectedSeverity.includes(item.severity)
    const matchesSearch = searchTerm === '' ||
      item.issue_id?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.asset_id?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.asset_name?.toLowerCase().includes(searchTerm.toLowerCase())
    return matchesFilter && matchesSearch
  })

  const groupedByAsset = filteredRemediations.reduce((acc, item) => {
    if (!acc[item.asset_id]) {
      acc[item.asset_id] = {
        asset_id: item.asset_id,
        asset_name: item.asset_name,
        asset_type: assetInfoMap[item.asset_id]?.asset_type || 'Unknown',
        issues: [],
        remediationCount: 0,
        uniqueRemediations: new Set()
      }
    }
    acc[item.asset_id].issues.push(item)
    acc[item.asset_id].remediationCount++
    acc[item.asset_id].uniqueRemediations.add(item.remediation)
    return acc
  }, {})

  const assetData = Object.values(groupedByAsset).map(asset => ({
    ...asset,
    uniqueRemediationCount: asset.uniqueRemediations.size
  }))

  const startIndex = (currentPage - 1) * itemsPerPage
  const tableData = viewMode === 'issue' ? filteredRemediations : assetData
  const totalPages = Math.ceil(tableData.length / itemsPerPage)
  const paginatedData = tableData.slice(startIndex, startIndex + itemsPerPage)

  const getSeverityClass = (severity) => {
    if (!severity) return 'low'
    const sev = severity.toUpperCase()
    if (sev === 'CRITICAL') return 'CRITICAL'
    if (sev === 'HIGH') return 'HIGH'
    if (sev === 'MEDIUM') return 'MEDIUM'
    return 'low'
  }

  const getActionClass = (action) => {
    if (action === 'Ticket Opened') return 'ticket-opened'
    if (action === 'Validated') return 'validated'
    if (action === 'Review the fix') return 'review-fix'
    return 'pending'
  }

  // Handle row click in Issue View - opens detail card
  const handleRowClick = (item) => {
    if (viewMode === 'issue') {
      setSelectedItem(item)
      setDetailOpen(true)
    }
  }

  // Handle row click in Asset View - opens side panel
  const handleAssetRowClick = (asset) => {
    setSelectedAsset(asset)
    setSelectedIssueInPanel(null)
  }

  // Handle issue click in panel - opens detail card
  const handleIssueInPanelClick = (issue, e) => {
    e.stopPropagation()
    setSelectedIssueInPanel(issue)
    setSelectedItem(issue)
    setDetailOpen(true)
  }

  // Close asset panel
  const closeAssetPanel = () => {
    setSelectedAsset(null)
    setSelectedIssueInPanel(null)
  }

  return (
    <div className="remediation-page-wrapper">
      <Topbar />
      <div className="remediation-layout">
        <Sidebar />
        <main className={`remediation-main ${selectedAsset ? 'with-panel' : ''}`}>
          <div className="remediation-header">
            <h1>Remediation</h1>
            <p className="remediation-subtitle">Track and manage vulnerability remediations across your infrastructure</p>
          </div>

          <div className="remediation-card">
            <div className="remediation-filters">
              <div className="remediation-chip active">
                {selectedSeverity.length === 0 ? 'All' : selectedSeverity.join(', ')}
                ({filteredRemediations.length})
              </div>
              <div className="remediation-toolbar">
                <div className="remediation-search">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <circle cx="11" cy="11" r="8"></circle>
                    <path d="m21 21-4.35-4.35"></path>
                  </svg>
                  <input
                    type="text"
                    placeholder="Search by issue ID, asset ID or name..."
                    value={searchTerm}
                    onChange={(e) => { setSearchTerm(e.target.value); setCurrentPage(1); }}
                  />
                </div>
                <ColumnToggle
                  data={remediations}
                  columns={remediationColumns}
                  visibleColumns={visibleColumns}
                  onChange={setVisibleColumns}
                />
                <SeverityFilter data={remediations} value={selectedSeverity} onChange={(val) => { setSelectedSeverity(val); setCurrentPage(1) }} />
                <ViewToggleEyeDropdown viewMode={viewMode} onChange={(mode) => { setViewMode(mode); setCurrentPage(1); setSelectedAsset(null); }} />
              </div>
            </div>

            <div className="remediation-table-container">
              <table className="remediation-table">
                <thead>
                  <tr>
                    {viewMode === 'issue' && (
                      <>
                        <th>ISSUE </th>
                        {isVisible('asset_name') && <th>ASSET</th>}
                      </>
                    )}

                    {viewMode === 'asset' && (
                      <>
                        <th>ASSET </th>
                        <th>ASSET TYPE</th>
                      </>
                    )}

                    {isVisible('severity') && <th>SEVERITY</th>}
                    {isVisible('sla') && viewMode === 'issue' && <th>SLA</th>}
                    {viewMode === 'asset' && <th>ISSUES</th>}
                    {isVisible('remediation') && <th>{viewMode === 'asset' ? 'REMEDIATIONS' : 'REMEDIATION'}</th>}
                    {isVisible('change_type') && <th>CHANGE TYPE</th>}
                    {isVisible('pathway') && <th>PATHWAY</th>}
                    {isVisible('action') && <th>ACTION</th>}
                  </tr>
                </thead>
                <tbody>
                  {paginatedData.length === 0 ? (
                    <tr><td colSpan="100" className="remediation-empty">No data found</td></tr>
                  ) : (
                    paginatedData.map((item) => (
                      <tr
                        key={viewMode === 'issue' ? item.issue_id : item.asset_id}
                        className={`remediation-row-clickable ${viewMode === 'asset' && selectedAsset?.asset_id === item.asset_id ? 'selected' : ''
                          }`}
                        onClick={() => viewMode === 'issue' ? handleRowClick(item) : handleAssetRowClick(item)}
                      >
                        {viewMode === 'issue' && (
                          <>
                            {isVisible('scanner_response') && (
                              <td>
                                <div className="combined-cell">
                                  <span className="remediation-issue-badge">{item.issue_id}</span>
                                  <span className="combined-secondary">{item.scanner_response}</span>
                                </div>
                              </td>
                            )}

                            {isVisible('asset_name') && (
                              <td className="remediation-cell-asset-name">{item.asset_name}</td>
                            )}
                          </>
                        )}

                        {/* ASSET VIEW: Asset ID, Asset Name, Asset Type (swapped) */}
                        {viewMode === 'asset' && (
                          <>
                            <td>
                              <div className="combined-cell">
                                <span className="remediation-asset-badge">
                                  {item.asset_id}
                                </span>
                                <span className="combined-secondary">
                                  {item.asset_name}
                                </span>
                              </div>
                            </td>

                            <td>
                              <span className="remediation-asset-type">
                                {item.asset_type}
                              </span>
                            </td>
                          </>
                        )}

                        {/* SEVERITY */}
                        {isVisible('severity') && (
                          <td>
                            {viewMode === 'issue' ? (
                              <span className={`remediation-severity ${getSeverityClass(item.severity)}`}>
                                {item.severity}
                              </span>
                            ) : (
                              <div className="severity-badges-row">
                                {(() => {
                                  // Count severities
                                  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
                                  item.issues?.forEach(issue => {
                                    const sev = issue.severity?.toUpperCase()
                                    if (counts.hasOwnProperty(sev)) counts[sev]++
                                  })

                                  // Render in priority order: C, H, M, L - only show non-zero
                                  const order = [
                                    { key: 'CRITICAL', letter: 'C', color: '#EF4444' },
                                    { key: 'HIGH', letter: 'H', color: '#F97316' },
                                    { key: 'MEDIUM', letter: 'M', color: '#EAB308' },
                                    { key: 'LOW', letter: 'L', color: '#10B981' }
                                  ]

                                  // Filter to only show severities that exist
                                  const existing = order.filter(({ key }) => counts[key] > 0)

                                  return existing.map(({ key, letter, color }, idx) => (
                                    <span
                                      key={key}
                                      className="severity-badge-group"
                                      title={`${counts[key]} ${key}`}
                                    >
                                      <span className="severity-count">{counts[key]}</span>
                                      <span
                                        className="severity-letter-badge"
                                        style={{
                                          background: `${color}20`,
                                          color: color,
                                          borderColor: `${color}40`
                                        }}
                                      >
                                        {letter}
                                      </span>
                                    </span>
                                  ))
                                })()}
                              </div>
                            )}
                          </td>
                        )}

                        {/* SLA Status (Issue view only) */}
                        {isVisible('sla') && viewMode === 'issue' && (
                          <td>
                            <SLABadge dateFound={item.date_found} severity={item.severity} />
                          </td>
                        )}

                        {/* ISSUES COUNT (Asset view only) - Just the number */}
                        {viewMode === 'asset' && (
                          <td>
                            <span className="remediation-count-badge issues">
                              {item.issues.length}
                            </span>
                          </td>
                        )}

                        {/* REMEDIATION */}
                        {isVisible('remediation') && (
                          <td className={viewMode === 'issue' ? 'remediation-cell-fix' : ''}>
                            {viewMode === 'issue'
                              ? item.remediation
                              : (
                                <span className="remediation-count-badge remediations">
                                  {item.uniqueRemediationCount}
                                </span>
                              )
                            }
                          </td>
                        )}

                        {/* CHANGE TYPE */}
                        {isVisible('change_type') && (
                          <td>{viewMode === 'issue' ? item.change_type : '—'}</td>
                        )}

                        {/* PATHWAY */}
                        {isVisible('pathway') && (
                          <td>
                            {viewMode === 'issue' ? (
                              <PathwayBadge item={item} />
                            ) : (
                              <span className="pathway-text-asset">
                                {getHighestRiskPathway(item.issues).pathway}
                              </span>
                            )}
                          </td>
                        )}

                        {/* ACTION */}
                        {isVisible('action') && (
                          <td>
                            {viewMode === 'issue' ? (
                              <span className={`remediation-action ${getActionClass(item.action)}`}>
                                {item.action}
                              </span>
                            ) : '—'}
                          </td>
                        )}
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            <div className="remediation-footer">
              <span className="remediation-count">
                Showing {startIndex + 1}-{Math.min(startIndex + itemsPerPage, tableData.length)} of {tableData.length} records
              </span>
              {totalPages > 1 && (
                <div className="remediation-pagination">
                  <button className="pagination-btn" onClick={() => setCurrentPage(p => Math.max(1, p - 1))} disabled={currentPage === 1}>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <polyline points="15 18 9 12 15 6"></polyline>
                    </svg>
                  </button>
                  {Array.from({ length: totalPages }, (_, i) => i + 1).map(page => (
                    <button
                      key={page}
                      className={`pagination-btn ${currentPage === page ? 'active' : ''}`}
                      onClick={() => setCurrentPage(page)}
                    >
                      {page}
                    </button>
                  ))}
                  <button className="pagination-btn" onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))} disabled={currentPage === totalPages}>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <polyline points="9 18 15 12 9 6"></polyline>
                    </svg>
                  </button>
                </div>
              )}
            </div>
          </div>
        </main>

        {/* Asset Issues Panel - Shows when asset row is clicked in Asset View */}
        {selectedAsset && viewMode === 'asset' && (
          <div className="remediation-issues-panel">
            <div className="issues-panel-header">
              <div className="issues-panel-title">
                <h3>{selectedAsset.asset_name}</h3>
                <span className="issues-panel-count">
                  {selectedAsset.issues.length} Issues
                </span>
              </div>
              <button className="issues-panel-close" onClick={closeAssetPanel}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18"></line>
                  <line x1="6" y1="6" x2="18" y2="18"></line>
                </svg>
              </button>
            </div>

            <div className="issues-panel-list">
              {selectedAsset.issues.map((issue) => {
                return (
                  <div
                    key={issue.issue_id}
                    className={`issue-panel-item ${selectedIssueInPanel?.issue_id === issue.issue_id ? 'selected' : ''}`}
                    onClick={(e) => handleIssueInPanelClick(issue, e)}
                  >
                    <div className="issue-panel-row">
                      <span className="issue-panel-id">{issue.issue_id}</span>
                      <span className={`issue-panel-severity ${issue.severity?.toLowerCase()}`}>
                        {issue.severity}
                      </span>
                    </div>
                    <div className="issue-panel-scanner">{issue.scanner_response}</div>
                    <div className="issue-panel-remediation">{issue.remediation}</div>
                    <div className="issue-panel-meta">
                      <span className="issue-panel-change">{issue.change_type}</span>
                      <span className={`issue-panel-action ${getActionClass(issue.action)}`}>
                        {issue.action}
                      </span>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        )}
      </div>

      {/* Horizontal Detail Card */}
      <RemediationDetailCard
        isOpen={detailOpen}
        onClose={() => setDetailOpen(false)}
        item={selectedItem}
      />
    </div>
  )
}