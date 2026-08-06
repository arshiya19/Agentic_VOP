import { useCallback, useEffect, useMemo, useState } from 'react'
import Sidebar from '../components/Sidebar'
import Topbar from '../components/Topbar'
import '../styles/Remediation.css'
import '../styles/RemediationPackages.css'

const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

// Pinned demo issue IDs — the 5 Phase-1 vulnerabilities.
const DEMO_ISSUE_IDS = [8585, 8586, 7481, 6394, 7832]

// Header "Remediate" button — hidden by default. Flip to true if you want
// to expose live LLM generation in the UI. Same behaviour as the CLI:
//   uv run python scripts/run_planner.py --persist
// Kept the handleGenerate function + API endpoint intact so re-enabling
// is a one-line change (no backend work).
const SHOW_REMEDIATE_BUTTON = false

const FAMILY_LABEL = {
  public_exposure: 'Public Exposure',
  network_exposure: 'Network Exposure',
  injection: 'Injection',
  vulnerable_dependency: 'Vulnerable Dependency',
  os_vulnerability: 'OS Vulnerability',
}

const STATUS_LABEL = {
  draft: 'Draft',
  awaiting_approval: 'Awaiting Approval',
  approved: 'Approved',
  rejected: 'Rejected',
  ready_for_execution: 'Ready for Execution',
}

const VALIDATION_TONE = {
  validated: 'good',
  partial: 'warn',
  unvalidated: 'bad',
}

const APPROVAL_LABEL = {
  auto: 'Auto',
  single_approver: 'Single Approver',
  multi_stage: 'Multi-stage',
}

function confidenceTone(score) {
  if (score >= 90) return 'good'
  if (score >= 75) return 'warn'
  return 'bad'
}

function formatDate(iso) {
  if (!iso) return '—'
  try {
    return new Date(iso).toLocaleString()
  } catch {
    return iso
  }
}

function recommendedPathway(pkg) {
  if (!pkg?.pathways || pkg.pathways.length === 0) return null
  const idx = pkg.recommended_pathway_index ?? 0
  return pkg.pathways[idx] || pkg.pathways[0]
}

export default function Remediation() {
  const [packages, setPackages] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [statusFilter, setStatusFilter] = useState('all')
  const [selectedId, setSelectedId] = useState(null)
  const [detail, setDetail] = useState(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [generating, setGenerating] = useState(false)
  const [toast, setToast] = useState(null)
  const [ticketStates, setTicketStates] = useState({}) // { [pkg_id]: { loading, status, url, id, error } }
  // Contextual switch: 'real' or 'demo'. Set by Integrations page buttons,
  // overridable via the pill at the top of the page.
  const [pipelineMode, setPipelineMode] = useState(
    () => localStorage.getItem('pipelineMode') || 'real'
  )

  // Listen for pipelineMode changes from other components / other tabs.
  useEffect(() => {
    const handler = () => {
      setPipelineMode(localStorage.getItem('pipelineMode') || 'real')
    }
    window.addEventListener('pipelineModeChanged', handler)
    window.addEventListener('storage', handler)
    return () => {
      window.removeEventListener('pipelineModeChanged', handler)
      window.removeEventListener('storage', handler)
    }
  }, [])

  const isDemo = pipelineMode === 'demo'
  const apiBase = isDemo
    ? `${API_URL}/admin/remediation-packages/demo`
    : `${API_URL}/admin/remediation-packages`

  const setModeManual = (mode) => {
    localStorage.setItem('pipelineMode', mode)
    window.dispatchEvent(new Event('pipelineModeChanged'))
  }

  const showToast = useCallback((kind, msg) => {
    setToast({ kind, msg })
    setTimeout(() => setToast(null), 3500)
  }, [])

  // silent=true skips the loading flash for background polls
  const refreshList = useCallback(async ({ silent = false } = {}) => {
    if (!silent) setLoading(true)
    setError(null)
    try {
      const url = statusFilter === 'all'
        ? apiBase
        : `${apiBase}?status=${statusFilter}`
      const res = await fetch(url)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      setPackages(data.packages || [])
    } catch (e) {
      setError(e.message || 'Failed to load packages')
      if (!silent) setPackages([])
    } finally {
      if (!silent) setLoading(false)
    }
  }, [statusFilter, apiBase])

  useEffect(() => { refreshList() }, [refreshList])

  // Clear selection when switching modes so demo/real packages don't bleed.
  useEffect(() => {
    setSelectedId(null)
    setDetail(null)
  }, [pipelineMode])

  // Poll silently while in demo mode so the list grows as the pipeline
  // generates packages — no loading-flash on each poll. Stop polling once
  // we've reached 5 packages (a full run's worth) to avoid infinite fetching.
  useEffect(() => {
    if (!isDemo) return
    if (packages.length >= 5) return
    const interval = setInterval(() => { refreshList({ silent: true }) }, 3000)
    return () => clearInterval(interval)
  }, [isDemo, refreshList, packages.length])

  // When a row is selected, load full detail (includes the pathways jsonb).
  useEffect(() => {
    if (selectedId == null) { setDetail(null); return }
    let cancelled = false
    setDetailLoading(true)
    fetch(`${apiBase}/${selectedId}`)
      .then(r => r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`)))
      .then(d => { if (!cancelled) setDetail(d) })
      .catch(e => { if (!cancelled) { setDetail(null); showToast('error', e.message) } })
      .finally(() => { if (!cancelled) setDetailLoading(false) })
    return () => { cancelled = true }
  }, [selectedId, showToast, apiBase])

  const handleGenerate = useCallback(async () => {
    if (generating) return
    setGenerating(true)
    try {
      const res = await fetch(`${API_URL}/admin/remediation-packages/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ issue_ids: DEMO_ISSUE_IDS }),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      const ok = data.packages?.filter(p => p.status === 'created').length || 0
      const total = data.packages?.length || 0
      showToast(ok === total ? 'success' : 'warn',
                `Generated ${ok}/${total} packages`)
      await refreshList()
    } catch (e) {
      showToast('error', `Generate failed: ${e.message}`)
    } finally {
      setGenerating(false)
    }
  }, [generating, refreshList, showToast])

  const handleApprove = useCallback(async (id) => {
    try {
      const res = await fetch(`${API_URL}/admin/remediation-packages/${id}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ approved_by: 'demo-user@acmecorp.com' }),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      showToast('success', `Package ${id} approved → ready for execution`)
      await refreshList()
      if (selectedId === id) {
        const refreshed = await fetch(`${API_URL}/admin/remediation-packages/${id}`).then(r => r.json())
        setDetail(refreshed)
      }
    } catch (e) {
      showToast('error', `Approve failed: ${e.message}`)
    }
  }, [refreshList, selectedId, showToast])

  const handleReject = useCallback(async (id) => {
    const reason = window.prompt('Reject reason (will be saved on the package):')
    if (!reason || reason.trim().length < 3) {
      showToast('warn', 'Reject canceled — reason must be ≥3 chars')
      return
    }
    try {
      const res = await fetch(`${API_URL}/admin/remediation-packages/${id}/reject`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: reason.trim(), rejected_by: 'demo-user@acmecorp.com' }),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      showToast('success', `Package ${id} rejected`)
      await refreshList()
      if (selectedId === id) {
        const refreshed = await fetch(`${API_URL}/admin/remediation-packages/${id}`).then(r => r.json())
        setDetail(refreshed)
      }
    } catch (e) {
      showToast('error', `Reject failed: ${e.message}`)
    }
  }, [refreshList, selectedId, showToast])

  const statusCounts = useMemo(() => {
    const out = { all: packages.length, awaiting_approval: 0, ready_for_execution: 0, rejected: 0 }
    for (const p of packages) {
      out[p.status] = (out[p.status] || 0) + 1
    }
    return out
  }, [packages])

  // For the stats strip we want totals across ALL statuses, not just the
  // current filter. Quick second fetch when filter isn't 'all'.
  const [globalStats, setGlobalStats] = useState({ total: 0, awaiting: 0, ready: 0, rejected: 0 })
  useEffect(() => {
    fetch(`${API_URL}/admin/remediation-packages`)
      .then(r => r.ok ? r.json() : { packages: [] })
      .then(d => {
        const list = d.packages || []
        setGlobalStats({
          total: list.length,
          awaiting: list.filter(p => p.status === 'awaiting_approval').length,
          ready: list.filter(p => p.status === 'ready_for_execution').length,
          rejected: list.filter(p => p.status === 'rejected').length,
        })
      })
      .catch(() => { /* ignore */ })
  }, [packages]) // refresh stats whenever the visible list changes

  return (
    <div className="remediation-page-wrapper">
      <Topbar />
      <div className="remediation-layout">
        <Sidebar />
        <main className="remediation-main">
          <div className="remediation-header rmp-header-flex">
            <div className="rmp-header-text">
              <h1>Remediation</h1>
              <p className="remediation-subtitle">
                Generated remediation packages — validated against authoritative sources, scored for confidence, gated by human approval.
                {isDemo && ' — DEMO PIPELINE (5 pre-seeded issues)'}
              </p>
            </div>
            <div style={{ display: 'flex', gap: 8, marginRight: 12 }}>
              <button
                type="button"
                onClick={() => setModeManual('real')}
                style={{
                  padding: '6px 14px',
                  borderRadius: 999,
                  border: '1px solid ' + (!isDemo ? '#22c55e' : '#334155'),
                  background: !isDemo ? 'rgba(34,197,94,0.15)' : 'transparent',
                  color: !isDemo ? '#22c55e' : '#94a3b8',
                  fontSize: 12, fontWeight: 600, cursor: 'pointer',
                }}
              >
                Real Pipeline
              </button>
              <button
                type="button"
                onClick={() => setModeManual('demo')}
                style={{
                  padding: '6px 14px',
                  borderRadius: 999,
                  border: '1px solid ' + (isDemo ? '#3b82f6' : '#334155'),
                  background: isDemo ? 'rgba(59,130,246,0.15)' : 'transparent',
                  color: isDemo ? '#3b82f6' : '#94a3b8',
                  fontSize: 12, fontWeight: 600, cursor: 'pointer',
                }}
              >
                Demo Pipeline
              </button>
            </div>
            {SHOW_REMEDIATE_BUTTON && (
              <button
                className="rmp-header-btn"
                onClick={handleGenerate}
                disabled={generating}
                type="button"
                title="Generate fresh remediation packages for the 5 demo issues"
              >
                {generating ? (
                  <>
                    <span className="rmp-header-btn-dot pulsing">●</span>
                    <span>Remediating…</span>
                  </>
                ) : (
                  <>
                    <span className="rmp-header-btn-dot">⚙</span>
                    <span>Remediate</span>
                  </>
                )}
              </button>
            )}
          </div>

          {/* Stats strip — 4 columns */}
          <div className="rmp-stats">
            <div className="rmp-stat-card">
              <div className="rmp-stat-num">{globalStats.total}</div>
              <div className="rmp-stat-label">Total Packages</div>
            </div>
            <div className="rmp-stat-card warn">
              <div className="rmp-stat-num">{globalStats.awaiting}</div>
              <div className="rmp-stat-label">Awaiting Approval</div>
            </div>
            <div className="rmp-stat-card good">
              <div className="rmp-stat-num">{globalStats.ready}</div>
              <div className="rmp-stat-label">Ready for Execution</div>
            </div>
            <div className="rmp-stat-card bad">
              <div className="rmp-stat-num">{globalStats.rejected}</div>
              <div className="rmp-stat-label">Rejected</div>
            </div>
          </div>

          {/* Toolbar — just filter pills now, action moved into stats strip */}
          <div className="rmp-toolbar">
            <div className="rmp-filter-group">
              {['all', 'awaiting_approval', 'ready_for_execution', 'rejected'].map(s => (
                <button
                  key={s}
                  className={`rmp-filter-pill ${statusFilter === s ? 'active' : ''}`}
                  onClick={() => setStatusFilter(s)}
                >
                  {s === 'all' ? 'All' : STATUS_LABEL[s]}
                  <span className="rmp-pill-count">{statusCounts[s] ?? 0}</span>
                </button>
              ))}
            </div>
          </div>

          {/* List */}
          <div className="rmp-list-card">
            {loading ? (
              <div className="rmp-empty">Loading packages…</div>
            ) : error ? (
              <div className="rmp-empty bad">Failed to load: {error}</div>
            ) : packages.length === 0 ? (
              <div className="rmp-empty">
                <div className="rmp-empty-title">No remediation packages yet</div>
                <div className="rmp-empty-sub">
                  Click <strong>Generate Demo Packages</strong> above to create one package per
                  demo finding (Sub-Agent 3 + Confidence Engine, ~90s).
                </div>
              </div>
            ) : (
              <table className="rmp-table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Finding</th>
                    <th>Family</th>
                    <th>Confidence</th>
                    <th>Validation</th>
                    <th>Approval</th>
                    <th>Status</th>
                    <th>Created</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {packages.map(p => {
                    // Cells receive the row and the current apiBase — in demo
                    // mode the row already carries `pathways` inline, so no
                    // N+1 fetch. In real mode they fall back to fetching from
                    // apiBase/{id} (the summary-only list doesn't include pathways).
                    return (
                      <tr key={p.id} className={selectedId === p.id ? 'selected' : ''}
                          onClick={() => setSelectedId(p.id)}>
                        <td>#{p.id}</td>
                        <td className="rmp-finding-cell">{p.finding || '—'}</td>
                        <td><span className="rmp-family-chip">{FAMILY_LABEL[p.family] || p.family}</span></td>
                        <td>
                          <ConfidenceCell pkg={p} apiBase={apiBase} />
                        </td>
                        <td>
                          <ValidationCell pkg={p} apiBase={apiBase} />
                        </td>
                        <td>{APPROVAL_LABEL[p.approval_required] || p.approval_required}</td>
                        <td><StatusPill status={p.status} /></td>
                        <td className="rmp-date-cell">{formatDate(p.created_at)}</td>
                        <td>
                          <button className="rmp-view-btn" onClick={(e) => { e.stopPropagation(); setSelectedId(p.id) }}>
                            View →
                          </button>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            )}
          </div>
        </main>

        {/* Detail drawer */}
        {selectedId != null && (
          <DetailDrawer
            pkg={detail}
            loading={detailLoading}
            onClose={() => { setSelectedId(null); setDetail(null) }}
            onApprove={() => handleApprove(selectedId)}
            onReject={() => handleReject(selectedId)}
          />
        )}

        {/* Toast */}
        {toast && (
          <div className={`rmp-toast ${toast.kind}`}>{toast.msg}</div>
        )}
      </div>
    </div>
  )
}


// =============================================================================
// Small per-row cells that lazily fetch confidence + validation from the
// detail endpoint. Caches a per-page so subsequent renders don't re-fetch.
// =============================================================================

const detailCache = new Map()

// If the row already carries `pathways` (demo endpoint includes it inline),
// skip the detail fetch. Otherwise fall back to fetching from apiBase — real
// mode uses the summary-only list endpoint and needs an N+1.
function useDetailField(pkg, apiBase) {
  const pkgId = pkg?.id
  const cacheKey = `${apiBase}|${pkgId}`
  const hasInlinePathways = Array.isArray(pkg?.pathways) && pkg.pathways.length > 0

  const [d, setD] = useState(() => {
    if (hasInlinePathways) return pkg
    return detailCache.get(cacheKey)
  })

  useEffect(() => {
    if (hasInlinePathways) { setD(pkg); return }
    if (d || detailCache.has(cacheKey)) return
    let cancelled = false
    fetch(`${apiBase}/${pkgId}`)
      .then(r => r.ok ? r.json() : null)
      .then(j => {
        if (cancelled || !j) return
        detailCache.set(cacheKey, j)
        setD(j)
      })
      .catch(() => {})
    return () => { cancelled = true }
  }, [pkgId, cacheKey, d, hasInlinePathways, pkg, apiBase])
  return d
}

function ConfidenceCell({ pkg, apiBase }) {
  const d = useDetailField(pkg, apiBase)
  const pw = recommendedPathway(d)
  if (!pw?.confidence_score) return <span className="rmp-muted">—</span>
  const tone = confidenceTone(pw.confidence_score)
  return (
    <div className={`rmp-conf-cell ${tone}`}>
      <span className="rmp-conf-num">{pw.confidence_score}</span>
      <div className="rmp-conf-bar"><div className="rmp-conf-fill" style={{ width: `${pw.confidence_score}%` }} /></div>
    </div>
  )
}

function ValidationCell({ pkg, apiBase }) {
  const d = useDetailField(pkg, apiBase)
  const pw = recommendedPathway(d)
  const vm = pw?.validation_metadata
  if (!vm) return <span className="rmp-muted">—</span>
  return <span className={`rmp-validation-pill ${VALIDATION_TONE[vm.status] || 'warn'}`}>{vm.status}</span>
}

function StatusPill({ status }) {
  return <span className={`rmp-status-pill st-${status}`}>{STATUS_LABEL[status] || status}</span>
}


// =============================================================================
// Detail drawer — the demo's hero view
// =============================================================================

function DetailDrawer({ pkg, loading, onClose, onApprove, onReject }) {
  const pw = recommendedPathway(pkg)
  const vm = pw?.validation_metadata
  const isTerminal = pkg?.status === 'ready_for_execution' || pkg?.status === 'rejected'
  const [ticketLoading, setTicketLoading] = useState(false)
  const [ticket, setTicket] = useState(null)

  return (
    <div className="rmp-drawer-overlay" onClick={onClose}>
      <div className="rmp-drawer" onClick={(e) => e.stopPropagation()}>
        <button className="rmp-drawer-close" onClick={onClose}>×</button>

        {loading || !pkg ? (
          <div className="rmp-drawer-body"><div className="rmp-empty">Loading…</div></div>
        ) : (
          <>
            <header className="rmp-drawer-header">
              <div className="rmp-drawer-title">
                <span className="rmp-drawer-id">#{pkg.id}</span>
                <span className="rmp-family-chip">{FAMILY_LABEL[pkg.family] || pkg.family}</span>
                <StatusPill status={pkg.status} />
              </div>
              <div className="rmp-drawer-meta">
                Issue {pkg.issue_id}  •  Created {formatDate(pkg.created_at)}
                {pkg.approved_by && <>  •  by {pkg.approved_by}</>}
              </div>
            </header>

            <div className="rmp-drawer-body">
              <section className="rmp-section">
                <h3>Finding</h3>
                <p>{pkg.finding}</p>
              </section>
              <section className="rmp-section">
                <h3>Root Cause</h3>
                <p>{pkg.root_cause}</p>
              </section>
              <section className="rmp-section">
                <h3>Impact</h3>
                <p>{pkg.impact}</p>
              </section>

              {pw && (
                <section className="rmp-section">
                  <div className="rmp-section-titlebar">
                    <h3>Recommended Pathway</h3>
                    <span className={`rmp-coverage-chip cov-${pw.security_coverage}`}>
                      {pw.security_coverage} coverage
                    </span>
                  </div>
                  <p className="rmp-objective">{pw.objective}</p>

                  {/* Remediation steps — collapsible, open by default (headline content) */}
                  <details className="rmp-collapsible" open>
                    <summary>Remediation Steps ({pw.remediation_steps?.length || 0})</summary>
                    <ol className="rmp-steps">
                      {pw.remediation_steps?.map((s, i) => (
                        <li key={i}>
                          <div className="rmp-step-text">{s.step}</div>
                          <SourceLink source={s.source} url={s.source_url} />
                        </li>
                      ))}
                    </ol>
                  </details>

                  {/* Rollback plan — collapsible, closed by default (secondary content) */}
                  {pw.rollback_plan && (
                    <details className="rmp-collapsible">
                      <summary>
                        Rollback Plan
                        <span className={`rmp-supported-chip ${pw.rollback_plan.supported ? 'good' : 'bad'}`}>
                          {pw.rollback_plan.supported ? 'supported' : 'not supported'}
                        </span>
                      </summary>
                      <div className="rmp-rollback">
                        <p className="rmp-objective">{pw.rollback_plan.objective}</p>
                        {pw.rollback_plan.preconditions?.length > 0 && (
                          <>
                            <h5>Preconditions</h5>
                            <ul>{pw.rollback_plan.preconditions.map((x, i) => <li key={i}>{x}</li>)}</ul>
                          </>
                        )}
                        {pw.rollback_plan.steps?.length > 0 && (
                          <>
                            <h5>Steps</h5>
                            <ol className="rmp-steps">
                              {pw.rollback_plan.steps.map((s, i) => (
                                <li key={i}>
                                  <div className="rmp-step-text">{s.step}</div>
                                  <SourceLink source={s.source} url={s.source_url} />
                                </li>
                              ))}
                            </ol>
                          </>
                        )}
                        {pw.rollback_plan.limitations?.length > 0 && (
                          <>
                            <h5>Limitations</h5>
                            <ul>{pw.rollback_plan.limitations.map((x, i) => <li key={i}>{x}</li>)}</ul>
                          </>
                        )}
                        {pw.rollback_plan.explanation && (
                          <>
                            <h5>Explanation</h5>
                            <p className="rmp-explanation">{pw.rollback_plan.explanation}</p>
                          </>
                        )}
                      </div>
                    </details>
                  )}

                  {/* Validation tests + test scripts */}
                  {pw.validation_tests?.length > 0 && (
                    <details className="rmp-collapsible">
                      <summary>Validation Tests ({pw.validation_tests.length})</summary>
                      <ul className="rmp-tests">
                        {pw.validation_tests.map((t, i) => (
                          <li key={i}>
                            <div className="rmp-test-name">{t.name}</div>
                            <pre className="rmp-test-cmd">{t.command}</pre>
                            <div className="rmp-test-exp">Expected: {t.expected}</div>
                            <SourceLink source={t.source} />
                          </li>
                        ))}
                      </ul>
                    </details>
                  )}

                  {pw.test_scripts?.length > 0 && (
                    <details className="rmp-collapsible">
                      <summary>Test Scripts ({pw.test_scripts.length})</summary>
                      {pw.test_scripts.map((ts, i) => (
                        <div key={i} className="rmp-script">
                          <div className="rmp-script-meta">{ts.language} — {ts.description}</div>
                          <pre className="rmp-script-code">{ts.code}</pre>
                        </div>
                      ))}
                    </details>
                  )}

                  {/* Confidence breakdown */}
                  {pw.confidence_components && (
                    <div className="rmp-confidence-block">
                      <h4>Confidence: {pw.confidence_score}/100</h4>
                      <div className="rmp-conf-grid">
                        {Object.entries(pw.confidence_components).map(([name, comp]) => (
                          <div key={name} className="rmp-conf-row">
                            <div className="rmp-conf-name">{name.replace(/_/g, ' ')}</div>
                            <div className="rmp-conf-bar wide">
                              <div className="rmp-conf-fill" style={{ width: `${(comp.score / comp.max_score) * 100}%` }} />
                            </div>
                            <div className="rmp-conf-val">{comp.score}/{comp.max_score}</div>
                            <div className="rmp-conf-reason">{comp.reason}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Execution strategy + advantages/considerations */}
                  <h4>Execution Strategy</h4>
                  <p>{pw.execution_strategy}</p>

                  {(pw.advantages?.length > 0 || pw.considerations?.length > 0) && (
                    <div className="rmp-adv-grid">
                      {pw.advantages?.length > 0 && (
                        <div>
                          <h5 className="good">Advantages</h5>
                          <ul>{pw.advantages.map((x, i) => <li key={i}>+ {x}</li>)}</ul>
                        </div>
                      )}
                      {pw.considerations?.length > 0 && (
                        <div>
                          <h5 className="warn">Considerations</h5>
                          <ul>{pw.considerations.map((x, i) => <li key={i}>– {x}</li>)}</ul>
                        </div>
                      )}
                    </div>
                  )}
                </section>
              )}

              {/* Validation metadata footer */}
              {vm && (
                <section className="rmp-section rmp-validation-footer">
                  <div className="rmp-vm-line">
                    <span className={`rmp-validation-pill ${VALIDATION_TONE[vm.status] || 'warn'}`}>
                      Validation: {vm.status}
                    </span>
                    <span className="rmp-vm-conf">Confidence: {vm.confidence}</span>
                    <span className="rmp-vm-when">{formatDate(vm.timestamp)}</span>
                  </div>
                  <div className="rmp-vm-sources">
                    📖 {vm.sources?.join(' · ')}
                  </div>
                </section>
              )}

              {pkg.rejected_reason && (
                <section className="rmp-section rejected-section">
                  <h4 className="bad">Rejection Reason</h4>
                  <p>{pkg.rejected_reason}</p>
                </section>
              )}
            </div>

            {/* Footer actions */}
            <footer className="rmp-drawer-footer">
              {isTerminal ? (
                <div className="rmp-terminal-state">
                  {pkg.status === 'ready_for_execution' ? (
                    <>
                      <span>✓ Approved — Ready for Execution</span>
                      {ticket ? (
                        <div className="rmp-ticket-info">
                          {ticket.status === 'created' ? (
                            <a
                              href={ticket.external_ticket_url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="rmp-ticket-link"
                            >
                              🎫 {ticket.external_ticket_id || 'Ticket'} ↗
                            </a>
                          ) : ticket.status === 'failed' ? (
                            <span className="rmp-ticket-error">⚠ Ticket creation failed: {ticket.error_message}</span>
                          ) : (
                            <span className="rmp-ticket-pending">⏳ Creating ticket…</span>
                          )}
                        </div>
                      ) : (
                        <button
                          className="rmp-btn rmp-btn-ticket"
                          disabled={ticketLoading}
                          onClick={async () => {
                            setTicketLoading(true)
                            try {
                              const res = await fetch(
                                `${API_URL}/admin/remediation-packages/${pkg.id}/create-ticket`,
                                { method: 'POST', headers: { 'Content-Type': 'application/json' } }
                              )
                              if (!res.ok) {
                                const err = await res.json().catch(() => ({}))
                                throw new Error(err.detail || `HTTP ${res.status}`)
                              }
                              const data = await res.json()
                              setTicket(data)
                            } catch (e) {
                              setTicket({ status: 'failed', error_message: e.message })
                            } finally {
                              setTicketLoading(false)
                            }
                          }}
                        >
                          {ticketLoading ? '⏳ Creating…' : '🎫 Create ServiceNow Ticket'}
                        </button>
                      )}
                    </>
                  ) : '✗ Rejected'}
                </div>
              ) : (
                <>
                  <button className="rmp-btn rmp-btn-reject" onClick={onReject}>Reject</button>
                  <button className="rmp-btn rmp-btn-approve" onClick={onApprove}>✓ Approve</button>
                </>
              )}
            </footer>
          </>
        )}
      </div>
    </div>
  )
}


function SourceLink({ source, url }) {
  if (!source) return null
  if (url) {
    return <a className="rmp-source" href={url} target="_blank" rel="noopener noreferrer">📖 {source} ↗</a>
  }
  return <span className="rmp-source rmp-source-flat">📖 {source}</span>
}
