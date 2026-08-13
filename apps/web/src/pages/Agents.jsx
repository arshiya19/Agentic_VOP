import { useEffect, useMemo, useState } from 'react'
import Topbar from '../components/Topbar'
import Sidebar from '../components/Sidebar'
import AgentModelConfig from '../components/AgentModelConfig'
import { supabase } from '../lib/supabase'
import '../styles/Agents.css'

const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'
const DEMO_POLL_MS = 2000

const ROLE_OPTIONS = [
  { key: 'all', label: 'All' },
  { key: 'master', label: 'Master' },
  { key: 'sub', label: 'Sub-agents' },
]

const EVENT_OPTIONS = [
  { key: 'all', label: 'All events' },
  { key: 'dispatch', label: 'Task dispatch' },
  { key: 'message', label: 'Message' },
  { key: 'result', label: 'Result' },
  { key: 'error', label: 'Error' },
]

const EVENT_TYPE_MAP = {
  DISPATCH: 'dispatch',
  DONE: 'result',
  MESSAGE: 'message',
  ERROR: 'error',
}

function deriveTo(row) {
  if (row.event_type === 'DISPATCH' && row.payload?.sub_agent_id) {
    return row.payload.sub_agent_id
  }
  if (row.event_type === 'DONE' || row.event_type === 'ERROR') {
    return 'master'
  }
  return null
}

function mapTraceRow(row) {
  return {
    id: row.id,
    from: row.agent,
    fromName: row.agent,
    to: deriveTo(row),
    toName: deriveTo(row),
    type: EVENT_TYPE_MAP[row.event_type] || 'message',
    taskId: row.payload?.correlation_id || null,
    message: row.message,
    timestamp: row.created_at,
    durationMs: row.payload?.duration_ms ?? null,
    payload: row.payload,
    runId: row.run_id,
  }
}

export default function Agents() {
  const [traceEvents, setTraceEvents] = useState([])
  const [runs, setRuns] = useState([])
  const [selectedAgent, setSelectedAgent] = useState('all')
  const [selectedEventType, setSelectedEventType] = useState('all')
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedTrace, setSelectedTrace] = useState(null)
  const [autoScroll, setAutoScroll] = useState(true)
  const [modelConfigOpen, setModelConfigOpen] = useState(false)
  const [showLogs, setShowLogs] = useState(false)
  // env2 reset state — button next to Real/Demo toggle
  const [resetting, setResetting] = useState(false)
  const [resetToast, setResetToast] = useState(null)  // { kind: 'success'|'error', message: string }
  const [dataLoaded, setDataLoaded] = useState(false)  // Track if initial data has been fetched
  // Contextual switch: 'real' (supabase realtime on public.*) or 'demo' (poll
  // backend demo endpoints). Set by Integrations page's trigger buttons; can
  // be overridden manually via the pill at the top of the page.
  const [pipelineMode, setPipelineMode] = useState(
    () => localStorage.getItem('pipelineMode') || 'real'
  )

  // Listen for pipelineMode changes from other components (Integrations page)
  // and from other tabs (native `storage` event).
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

  useEffect(() => {
    let mounted = true

    // Clear both lists when switching modes so demo/real never bleed into each other.
    setTraceEvents([])
    setRuns([])
    setSelectedTrace(null)

    if (pipelineMode === 'demo') {
      // ----- Demo mode: poll backend endpoints (no realtime on demo schema) -----
      const poll = async () => {
        try {
          const runsRes = await fetch(`${API_URL}/agents/demo/runs`)
          if (!mounted || !runsRes.ok) return
          const runsData = await runsRes.json()
          if (!mounted) return
          const demoRuns = runsData.runs || []
          setRuns(demoRuns)

          // Fetch traces for ALL demo runs so the trace stream shows every run.
          const allTraces = []
          for (const r of demoRuns.slice(0, 5)) {
            try {
              const tRes = await fetch(`${API_URL}/agents/demo/runs/${r.run_id}/traces`)
              if (!tRes.ok) continue
              const tData = await tRes.json()
              allTraces.push(...(tData.traces || []))
            } catch { /* skip this run's traces */ }
          }
          if (!mounted) return
          // Sort DESC (newest first) to match real-mode display.
          allTraces.sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
          setTraceEvents(allTraces.map(mapTraceRow))
        } catch { /* transient network error, retry next tick */ }
      }
      poll()
      const interval = setInterval(poll, DEMO_POLL_MS)
      return () => {
        mounted = false
        clearInterval(interval)
      }
    }

    // ----- Real mode: existing supabase realtime on public.* (unchanged) -----
    supabase
      .from('agent_trace_events')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(200)
      .then(({ data, error }) => {
        if (!mounted || error || !data) return
        setTraceEvents(data.map(mapTraceRow))
      })

    const traceChannel = supabase
      .channel('agent-trace-stream')
      .on(
        'postgres_changes',
        { event: 'INSERT', schema: 'public', table: 'agent_trace_events' },
        (payload) => {
          if (!mounted) return
          setTraceEvents((prev) => [mapTraceRow(payload.new), ...prev])
        }
      )
      .subscribe()

    supabase
      .from('agent_runs')
      .select('*')
      .order('started_at', { ascending: false })
      .limit(100)
      .then(({ data, error }) => {
        if (!mounted || error || !data) return
        setRuns(data)
      })

    const runsChannel = supabase
      .channel('agent-runs-stream')
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'agent_runs' },
        (payload) => {
          if (!mounted) return
          if (payload.eventType === 'INSERT') {
            setRuns((prev) => [payload.new, ...prev])
          } else if (payload.eventType === 'UPDATE') {
            setRuns((prev) =>
              prev.map((r) => (r.run_id === payload.new.run_id ? payload.new : r))
            )
          }
        }
      )
      .subscribe()

    return () => {
      mounted = false
      supabase.removeChannel(traceChannel)
      supabase.removeChannel(runsChannel)
    }
  }, [pipelineMode])

  const setModeManual = (mode) => {
    localStorage.setItem('pipelineMode', mode)
    window.dispatchEvent(new Event('pipelineModeChanged'))
  }

  const handleResetEnv2 = async () => {
    if (resetting) return
    const ok = window.confirm(
      "Reset env2 to the vulnerable baseline?\n\n" +
      "This will:\n" +
      "  • terraform destroy the current lab resources\n" +
      "  • wipe S3 terraform state + DynamoDB lock\n" +
      "  • restore main.tf from main.tf.original\n" +
      "  • terraform apply the fresh vulnerable baseline\n\n" +
      "Takes ~60 seconds. Do not trigger a demo run during this."
    )
    if (!ok) return
    setResetting(true)
    setResetToast(null)
    try {
      const res = await fetch(`${API_URL}/admin/env2/reset`, { method: 'POST' })
      const body = await res.json().catch(() => ({}))
      if (!res.ok) {
        const detail = typeof body?.detail === 'string' ? body.detail : JSON.stringify(body?.detail || body)
        setResetToast({ kind: 'error', message: `Reset failed: ${detail.slice(0, 300)}` })
      } else {
        const bits = []
        if (body.checkov_failed != null) bits.push(`${body.checkov_failed} checkov failures`)
        if (body.new_sg_id) bits.push(`new SG ${body.new_sg_id}`)
        if (body.duration_s != null) bits.push(`${body.duration_s}s`)
        setResetToast({
          kind: 'success',
          message: `✅ env2 cleaned — ${bits.join(' · ') || 'ready'}`,
        })
      }
    } catch (e) {
      setResetToast({ kind: 'error', message: `Reset request failed: ${e.message || e}` })
    } finally {
      setResetting(false)
    }
  }

  // Auto-dismiss the reset toast after 8s so it doesn't cover the trace
  useEffect(() => {
    if (!resetToast) return
    const t = setTimeout(() => setResetToast(null), 8000)
    return () => clearTimeout(t)
  }, [resetToast])

  // ----- Stage mapping and current stage detection -----
  const STAGES = [
    { id: 'connector', name: 'Smart Connector', agent: 'sub-agent-1' },
    { id: 'enrichment', name: 'Enrichment Specialist', agent: 'sub-agent-2' },
    { id: 'planning', name: 'Remediation Planner', agent: 'sub-agent-3' },
    { id: 'fixing', name: 'Fixer', agent: 'sub-agent-4' },
  ]

  const getCurrentStage = () => {
    const activeRunIds = new Set(
      runs.filter((r) => r.status === 'running').map((r) => r.run_id)
    )
    
    if (activeRunIds.size === 0) return null

    // Find the most recent event from any agent to determine current stage
    for (let i = 0; i < traceEvents.length; i++) {
      const event = traceEvents[i]
      if (activeRunIds.has(event.runId)) {
        // Match agent to stage
        for (let s = STAGES.length - 1; s >= 0; s--) {
          const stage = STAGES[s]
          if (event.from === stage.agent || event.from === 'master') {
            return stage.id
          }
        }
        break
      }
    }
    return null
  }

  const currentStage = useMemo(() => getCurrentStage(), [traceEvents, runs])

  // ----- Derived: agents (master + 4 sub-agents with live status) -----
  // "working" = the agent has emitted at least one trace event for an
  // actively running run. Stays green for the entire duration of the run,
  // not just 30s after the last event (SA-4 can take 60s+ between events
  // during terraform apply).
  const agents = useMemo(() => {
    const activeRunIds = new Set(
      runs.filter((r) => r.status === 'running').map((r) => r.run_id)
    )

    const isActiveInRun = (agentName) => {
      if (activeRunIds.size === 0) return false
      return traceEvents.some(
        (e) => e.from === agentName && activeRunIds.has(e.runId)
      )
    }

    const lastEventFor = (agentName) => {
      const events = traceEvents.filter((e) => e.from === agentName)
      return events[events.length - 1] || null
    }

    const masterEvent = lastEventFor('master')
    const sub1Event = lastEventFor('sub-agent-1')
    const sub2Event = lastEventFor('sub-agent-2')
    const sub3Event = lastEventFor('sub-agent-3')
    const sub4Event = lastEventFor('sub-agent-4')

    return [
      {
        id: 'master',
        name: 'Master Orchestrator',
        role: 'master',
        status: isActiveInRun('master') ? 'working' : 'idle',
        currentTask: masterEvent?.message || null,
      },
      {
        id: 'sub-agent-1',
        name: 'Sub-Agent 1 — Smart Connector',
        role: 'sub',
        status: isActiveInRun('sub-agent-1') ? 'working' : 'idle',
        currentTask: sub1Event?.message || null,
      },
      {
        id: 'sub-agent-2',
        name: 'Sub-Agent 2 — Enrichment Specialist',
        role: 'sub',
        status: isActiveInRun('sub-agent-2') ? 'working' : 'idle',
        currentTask: sub2Event?.message || null,
      },
      {
        id: 'sub-agent-3',
        name: 'Sub-Agent 3 — Remediation Planner',
        role: 'sub',
        status: isActiveInRun('sub-agent-3') ? 'working' : 'idle',
        currentTask: sub3Event?.message || null,
      },
      {
        id: 'sub-agent-4',
        name: 'Sub-Agent 4 — Fixer',
        role: 'sub',
        status: isActiveInRun('sub-agent-4') ? 'working' : 'idle',
        currentTask: sub4Event?.message || null,
      },
    ]
  }, [runs, traceEvents])

  // ----- Derived: live KPI stats for the 4 cards at the top -----
  const stats = useMemo(() => {
    const today = new Date()
    today.setHours(0, 0, 0, 0)

    const activeRuns = runs.filter((r) => r.status === 'running').length
    const queuedRuns = runs.filter((r) => r.status === 'queued').length

    const completedTodayRuns = runs.filter(
      (r) =>
        r.status === 'completed' &&
        r.completed_at &&
        new Date(r.completed_at) >= today
    )

    const avgDurationMs =
      completedTodayRuns.length > 0
        ? completedTodayRuns.reduce(
            (acc, r) =>
              acc + (new Date(r.completed_at) - new Date(r.started_at)),
            0
          ) / completedTodayRuns.length
        : 0

    const avgDuration =
      avgDurationMs > 0
        ? avgDurationMs >= 60000
          ? `${(avgDurationMs / 60000).toFixed(1)}m`
          : `${(avgDurationMs / 1000).toFixed(0)}s`
        : '—'

    const errorEventsToday = traceEvents.filter(
      (e) => e.type === 'error' && new Date(e.timestamp) >= today
    )

    return {
      activeAgents: activeRuns > 0 ? 5 : 0,   // 1 master + 4 sub-agents
      activeMasters: activeRuns > 0 ? 1 : 0,
      activeSubs: activeRuns > 0 ? 4 : 0,
      tasksInFlight: activeRuns,
      tasksQueued: queuedRuns,
      completedToday: completedTodayRuns.length,
      avgDuration,
    }
  }, [runs, traceEvents])

  const agentFilterOptions = useMemo(() => {
    const base = [{ key: 'all', label: 'All agents' }]
    return base.concat(
      agents.map(a => ({ key: a.id, label: a.name }))
    )
  }, [agents])

  const filteredEvents = useMemo(() => {
    return traceEvents.filter(ev => {
      const matchesAgent =
        selectedAgent === 'all' ||
        ev.from === selectedAgent ||
        ev.to === selectedAgent
      const matchesType =
        selectedEventType === 'all' || ev.type === selectedEventType
      const matchesSearch =
        searchTerm === '' ||
        ev.taskId?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        ev.message?.toLowerCase().includes(searchTerm.toLowerCase())
      return matchesAgent && matchesType && matchesSearch
    })
  }, [traceEvents, selectedAgent, selectedEventType, searchTerm])

  const masterAgents = agents.filter(a => a.role === 'master')
  const subAgents = agents.filter(a => a.role === 'sub')

  const formatTime = (iso) => {
    if (!iso) return '—'
    try {
      return new Date(iso).toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      })
    } catch {
      return iso
    }
  }

  const getStatusClass = (status) => {
    if (!status) return 'idle'
    const s = status.toLowerCase()
    if (s === 'working' || s === 'running') return 'working'
    if (s === 'error' || s === 'failed') return 'error'
    if (s === 'done' || s === 'completed') return 'done'
    return 'idle'
  }

  const getEventClass = (type) => {
    if (type === 'dispatch') return 'dispatch'
    if (type === 'result') return 'result'
    if (type === 'error') return 'error'
    return 'message'
  }

  const handleClearTrace = () => {
    // Wire to your backend when ready
  }

  // ProgressFlow component
  const ProgressFlow = () => {
    const isRunning = runs.some((r) => r.status === 'running')
    // Only show completed state if the MOST RECENT run is completed (and nothing is running)
    const mostRecentRun = runs.length > 0 ? runs[0] : null
    const hasCompletedRun = !isRunning && mostRecentRun && mostRecentRun.status === 'completed'

    return (
      <div className="progress-flow-container">
        <div className="progress-flow-header">
    
          <p className="progress-flow-description">Agent pipeline execution</p>
        </div>
        {!isRunning && currentStage === null ? (
          <div className="progress-flow-empty">
            <svg viewBox="0 0 64 64" className="empty-icon">
              <circle cx="32" cy="32" r="30" fill="none" stroke="currentColor" strokeWidth="2" opacity="0.3" />
              <path d="M32 16v32M16 32h32" stroke="currentColor" strokeWidth="2" opacity="0.3" strokeLinecap="round" />
            </svg>
            <p className="empty-title">No Active Run</p>
            <p className="empty-description">Start a pipeline run to see progress</p>
          </div>
        ) : (
          <div className="progress-flow">
            {STAGES.map((stage, idx) => {
              // When run completes, show all stages as completed
              const isCompleted = hasCompletedRun || (
                currentStage &&
                STAGES.findIndex((s) => s.id === currentStage) > idx
              )
              const isCurrent = currentStage === stage.id && isRunning
              const isUpcoming =
                currentStage &&
                STAGES.findIndex((s) => s.id === currentStage) < idx &&
                !hasCompletedRun

              return (
                <div key={stage.id} className="progress-stage-vertical-wrapper">
                  <div
                    className={`progress-stage ${isCurrent ? 'current' : ''} ${
                      isCompleted ? 'completed' : ''
                    } ${isUpcoming ? 'upcoming' : ''}`}
                  >
                    <div className="stage-indicator">
                      {isCompleted ? (
                        <svg className="stage-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
                          <polyline points="20 6 9 17 4 12"></polyline>
                        </svg>
                      ) : isCurrent ? (
                        <>
                          <span className="stage-dot"></span>
                          <span className="stage-pulse"></span>
                        </>
                      ) : (
                        <span className="stage-number">{idx + 1}</span>
                      )}
                    </div>
                    <div className="stage-info">
                      <div className="stage-name">{stage.name}</div>
                      <div className="stage-details">
                        {isCurrent && isRunning && (
                          <span className="stage-badge current-badge">
                            <span className="badge-dot"></span>
                            Processing
                          </span>
                        )}
                        {isCompleted && (
                          <span className="stage-badge completed-badge">
                            <span className="badge-dot"></span>
                            {hasCompletedRun && !isRunning ? 'Completed' : 'Done'}
                          </span>
                        )}
                        {isUpcoming && (
                          <span className="stage-badge upcoming-badge">
                            <span className="badge-dot"></span>
                            Queued
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                  {idx < STAGES.length - 1 && (
                    <div className={`progress-connector-vertical ${isCompleted || isCurrent ? 'active' : ''} ${hasCompletedRun ? 'completed' : ''}`}>
                      <div className="vertical-arrow">↓</div>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>
    )
  }

  const handleStopActiveRun = async () => {
    const activeRun = runs.find(r => r.status === 'running' || r.status === 'queued')
    if (!activeRun) return

    const scanners = (activeRun.targets?.scanners || []).join(', ') || 'this scanner'
    const ok = window.confirm(
      `Stop the running fetch?\n\n` +
      `This will:\n` +
      `  • Halt the fetch immediately\n` +
      `  • DELETE all issues and raw_findings for ${scanners}\n` +
      `  • Reset the watermark so the next fetch starts fresh\n\n` +
      `Continue?`
    )
    if (!ok) return

    const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'
    try {
      const res = await fetch(`${API_URL}/agents/runs/${activeRun.run_id}/cancel`, {
        method: 'POST',
      })
      if (!res.ok) {
        const txt = await res.text()
        alert(`Failed to stop run: ${res.status} — ${txt}`)
        return
      }
      const data = await res.json()
      alert(
        `Stopped run ${data.run_id}\n\n` +
        `Scanners cleaned: ${data.scanners_cleaned.join(', ')}\n` +
        `Issues deleted: ${data.issues_deleted}\n` +
        `Raw findings deleted: ${data.raw_findings_deleted}`
      )
    } catch (err) {
      alert(`Network error stopping run: ${err.message || err}`)
    }
  }

  return (
    <div className="agents-page-wrapper">
      <Topbar />
      <div className="agents-layout">
        <Sidebar />
        <main className="agents-main">
          <div className="agents-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <h1>Agents</h1>
              <p className="agents-subtitle">
                Live trace of master agent and sub-agent communication
                {pipelineMode === 'demo' && ' — DEMO PIPELINE (5 pre-seeded issues)'}
              </p>
            </div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
              <button
                type="button"
                onClick={handleResetEnv2}
                disabled={resetting}
                title="Destroy + recreate env2 to the vulnerable baseline (~60s)"
                style={{
                  padding: '6px 14px',
                  borderRadius: 999,
                  border: '1px solid ' + (resetting ? '#334155' : '#f59e0b'),
                  background: resetting ? 'transparent' : 'rgba(245,158,11,0.12)',
                  color: resetting ? '#94a3b8' : '#f59e0b',
                  fontSize: 12, fontWeight: 600,
                  cursor: resetting ? 'wait' : 'pointer',
                  display: 'inline-flex', alignItems: 'center', gap: 6,
                }}
              >
                {resetting ? (
                  <>
                    <span style={{
                      width: 10, height: 10, border: '2px solid currentColor',
                      borderTopColor: 'transparent', borderRadius: '50%',
                      animation: 'spin 0.8s linear infinite', display: 'inline-block',
                    }} />
                    Resetting env2…
                  </>
                ) : (
                  <>🧹 Reset env2</>
                )}
              </button>
              <button
                type="button"
                onClick={() => setModeManual('real')}
                style={{
                  padding: '6px 14px',
                  borderRadius: 999,
                  border: '1px solid ' + (pipelineMode === 'real' ? '#22c55e' : '#334155'),
                  background: pipelineMode === 'real' ? 'rgba(34,197,94,0.15)' : 'transparent',
                  color: pipelineMode === 'real' ? '#22c55e' : '#94a3b8',
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
                  border: '1px solid ' + (pipelineMode === 'demo' ? '#3b82f6' : '#334155'),
                  background: pipelineMode === 'demo' ? 'rgba(59,130,246,0.15)' : 'transparent',
                  color: pipelineMode === 'demo' ? '#3b82f6' : '#94a3b8',
                  fontSize: 12, fontWeight: 600, cursor: 'pointer',
                }}
              >
                Demo Pipeline
              </button>
            </div>
          </div>

          {resetToast && (
            <div
              role="status"
              style={{
                marginTop: 8,
                padding: '8px 14px',
                borderRadius: 8,
                fontSize: 13,
                border: '1px solid ' + (resetToast.kind === 'success' ? '#22c55e' : '#ef4444'),
                background: resetToast.kind === 'success' ? 'rgba(34,197,94,0.08)' : 'rgba(239,68,68,0.08)',
                color: resetToast.kind === 'success' ? '#22c55e' : '#ef4444',
              }}
            >
              {resetToast.message}
            </div>
          )}

          <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>

          <div className="agents-stats-row">
            <div className="agent-stat-card">
              <div className="agent-stat-value">{stats.activeAgents ?? '—'}</div>
              <div className="agent-stat-label">Active Agents</div>
              <div className="agent-stat-sub">
                Master: {stats.activeMasters ?? '—'} &nbsp;|&nbsp; Sub: {stats.activeSubs ?? '—'}
              </div>
            </div>
            <div className="agent-stat-card">
              <div className="agent-stat-value">{stats.tasksInFlight ?? '—'}</div>
              <div className="agent-stat-label">Tasks In Flight</div>
              <div className="agent-stat-sub">
                Queued: {stats.tasksQueued ?? '—'}
              </div>
            </div>
            <div className="agent-stat-card">
              <div className="agent-stat-value">{stats.completedToday ?? '—'}</div>
              <div className="agent-stat-label">Completed (today)</div>
              <div className="agent-stat-sub">
                Avg duration: {stats.avgDuration ?? '—'}
              </div>
            </div>
          </div>

          <div className="agents-content-grid">
            <aside className="agents-side-card">
              <div className="agents-card-header">
                <div className="agents-card-header-left">
                  <h2>Agents</h2>
                  <button
                    className="amc-trigger amc-trigger-icon"
                    onClick={() => setModelConfigOpen(true)}
                    title="Configure which LLM each agent uses"
                    aria-label="Configure agent models"
                  >
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <circle cx="12" cy="12" r="3"></circle>
                      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
                    </svg>
                  </button>
                </div>
                <div className="agents-role-tabs">
                  {ROLE_OPTIONS.map(opt => (
                    <button
                      key={opt.key}
                      className={`role-tab ${
                        selectedAgent === 'all' && opt.key === 'all'
                          ? 'active'
                          : ''
                      }`}
                      onClick={() => setSelectedAgent('all')}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>
              </div>

              <div className="agents-list">
                <div className="agents-group-label">Master</div>
                {masterAgents.length === 0 ? (
                  <div className="agents-empty-row">No master agent registered</div>
                ) : (
                  masterAgents.map(agent => (
                    <button
                      key={agent.id}
                      className={`agent-row ${
                        selectedAgent === agent.id ? 'selected' : ''
                      }`}
                      onClick={() => setSelectedAgent(agent.id)}
                    >
                      <span className={`agent-status-dot ${getStatusClass(agent.status)}`}></span>
                      <div className="agent-row-body">
                        <div className="agent-row-name">{agent.name}</div>
                        <div className="agent-row-task">
                          {agent.currentTask || 'Idle'}
                        </div>
                      </div>
                      <span className="agent-role-badge master">M</span>
                    </button>
                  ))
                )}

                <div className="agents-group-label">Sub-agents</div>
                {subAgents.length === 0 ? (
                  <div className="agents-empty-row">No sub-agents registered</div>
                ) : (
                  subAgents.map(agent => (
                    <button
                      key={agent.id}
                      className={`agent-row ${
                        selectedAgent === agent.id ? 'selected' : ''
                      }`}
                      onClick={() => setSelectedAgent(agent.id)}
                    >
                      <span className={`agent-status-dot ${getStatusClass(agent.status)}`}></span>
                      <div className="agent-row-body">
                        <div className="agent-row-name">{agent.name}</div>
                        <div className="agent-row-task">
                          {agent.currentTask || 'Idle'}
                        </div>
                      </div>
                      <span className="agent-role-badge sub">S</span>
                    </button>
                  ))
                )}
              </div>
            </aside>

            <section className="agents-trace-card">
              <div className="agents-card-header">
                <h2>Communication Trace</h2>
                <div className="trace-toolbar">
                  <div className="trace-search">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <circle cx="11" cy="11" r="8"></circle>
                      <path d="m21 21-4.35-4.35"></path>
                    </svg>
                    <input
                      type="text"
                      placeholder="Search by task ID or message..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                    />
                  </div>

                  <select
                    className="trace-select"
                    value={selectedAgent}
                    onChange={(e) => setSelectedAgent(e.target.value)}
                  >
                    {agentFilterOptions.map(opt => (
                      <option key={opt.key} value={opt.key}>
                        {opt.label}
                      </option>
                    ))}
                  </select>

                  <select
                    className="trace-select"
                    value={selectedEventType}
                    onChange={(e) => setSelectedEventType(e.target.value)}
                  >
                    {EVENT_OPTIONS.map(opt => (
                      <option key={opt.key} value={opt.key}>
                        {opt.label}
                      </option>
                    ))}
                  </select>

                  <label className="trace-toggle">
                    <input
                      type="checkbox"
                      checked={autoScroll}
                      onChange={(e) => setAutoScroll(e.target.checked)}
                    />
                    <span>Auto-scroll</span>
                  </label>

                  <label className="trace-toggle">
                    <input
                      type="checkbox"
                      checked={showLogs}
                      onChange={(e) => setShowLogs(e.target.checked)}
                    />
                    <span>Show Logs</span>
                  </label>

                  <button className="trace-btn" onClick={handleClearTrace} title="Clear trace">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <polyline points="3 6 5 6 21 6"></polyline>
                      <path d="M19 6l-2 14a2 2 0 0 1-2 2H9a2 2 0 0 1-2-2L5 6"></path>
                    </svg>
                  </button>
                  {runs.some(r => r.status === 'running' || r.status === 'queued') && (
                    <button
                      className="trace-btn trace-btn-stop"
                      onClick={handleStopActiveRun}
                      title="Stop the running fetch and wipe its scanner's data"
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
                        <rect x="6" y="6" width="12" height="12" rx="1"></rect>
                      </svg>
                      <span style={{ marginLeft: 6, fontSize: 12 }}>Stop</span>
                    </button>
                  )}
                </div>
              </div>

              {/* somewhere here */}

              {!showLogs && <ProgressFlow />}

              <div className="trace-stream" style={{ display: showLogs ? 'block' : 'none' }}>
                {filteredEvents.length === 0 ? (
                  <div className="trace-empty">
                    <div className="trace-empty-title">Waiting for agent activity</div>
                    <div className="trace-empty-sub">
                      Once the master agent dispatches a task, every message and
                      result will stream in here.
                    </div>
                  </div>
                ) : (
                  filteredEvents.map(ev => (
                    <div
                      key={ev.id}
                      className={`trace-event ${getEventClass(ev.type)} ${
                        selectedTrace?.id === ev.id ? 'selected' : ''
                      }`}
                      onClick={() => setSelectedTrace(ev)}
                    >
                      <div className="trace-event-time">{formatTime(ev.timestamp)}</div>
                      <div className={`trace-event-arrow ${getEventClass(ev.type)}`}>
                        <span className="arrow-from">{ev.fromName || ev.from || '—'}</span>
                        <span className="arrow-symbol">→</span>
                        <span className="arrow-to">{ev.toName || ev.to || '—'}</span>
                      </div>
                      <div className="trace-event-body">
                        <span className={`trace-type-badge ${getEventClass(ev.type)}`}>
                          {ev.type || 'message'}
                        </span>
                        {ev.taskId && (
                          <span className="trace-task-id">{ev.taskId}</span>
                        )}
                        <span className="trace-message">{ev.message}</span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </section>
          </div>

          {selectedTrace && (
            <div className="trace-detail-overlay" onClick={() => setSelectedTrace(null)}>
              <div className="trace-detail-drawer" onClick={(e) => e.stopPropagation()}>
                <div className="trace-detail-header">
                  <h3>Trace Detail</h3>
                  <button
                    className="trace-detail-close"
                    onClick={() => setSelectedTrace(null)}
                  >
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <line x1="18" y1="6" x2="6" y2="18"></line>
                      <line x1="6" y1="6" x2="18" y2="18"></line>
                    </svg>
                  </button>
                </div>
                <dl className="trace-detail-grid">
                  <dt>Task ID</dt>
                  <dd>{selectedTrace.taskId || '—'}</dd>
                  <dt>Type</dt>
                  <dd>{selectedTrace.type || '—'}</dd>
                  <dt>From</dt>
                  <dd>{selectedTrace.fromName || selectedTrace.from || '—'}</dd>
                  <dt>To</dt>
                  <dd>{selectedTrace.toName || selectedTrace.to || '—'}</dd>
                  <dt>Timestamp</dt>
                  <dd>{selectedTrace.timestamp || '—'}</dd>
                  <dt>Duration</dt>
                  <dd>{selectedTrace.durationMs != null ? `${selectedTrace.durationMs} ms` : '—'}</dd>
                </dl>
                <div className="trace-detail-section">
                  <div className="trace-detail-section-label">Message</div>
                  <pre className="trace-detail-payload">
                    {selectedTrace.message || '—'}
                  </pre>
                </div>
                {selectedTrace.payload?.missed_cves?.length > 0 && (
                  <div className="trace-detail-section">
                    <div className="trace-detail-section-label">
                      Cache-missed CVEs ({selectedTrace.payload.missed_cve_count ?? selectedTrace.payload.missed_cves.length}) — went to NVD API
                    </div>
                    <ul className="trace-detail-cve-list">
                      {selectedTrace.payload.missed_cves.map((cve) => (
                        <li key={cve}>
                          <a
                            href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                            target="_blank"
                            rel="noopener noreferrer"
                          >
                            {cve}
                          </a>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                <div className="trace-detail-section">
                  <div className="trace-detail-section-label">Payload</div>
                  <pre className="trace-detail-payload">
                    {selectedTrace.payload
                      ? JSON.stringify(selectedTrace.payload, null, 2)
                      : '—'}
                  </pre>
                </div>
              </div>
            </div>
          )}
        </main>
      </div>
      <AgentModelConfig open={modelConfigOpen} onClose={() => setModelConfigOpen(false)} />
    </div>
  )
}
