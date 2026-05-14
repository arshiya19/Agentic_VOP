import { useEffect, useMemo, useState } from 'react'
import Topbar from '../components/Topbar'
import Sidebar from '../components/Sidebar'
import AgentModelConfig from '../components/AgentModelConfig'
import { supabase } from '../lib/supabase'
import '../styles/Agents.css'

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

  useEffect(() => {
    let mounted = true

    // ----- Trace events: initial load + Realtime stream (newest on top) -----
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
          // Prepend so newest event appears at the top
          setTraceEvents((prev) => [mapTraceRow(payload.new), ...prev])
        }
      )
      .subscribe()

    // ----- Agent runs: initial load + Realtime stream (INSERT + UPDATE) -----
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
  }, [])

  // ----- Derived: agents (master + 2 sub-agents with live status) -----
  const agents = useMemo(() => {
    const activeRunIds = new Set(
      runs.filter((r) => r.status === 'running').map((r) => r.run_id)
    )

    const lastEventFor = (agentName) => {
      const events = traceEvents.filter(
        (e) => e.from === agentName && activeRunIds.has(e.runId)
      )
      return events[events.length - 1]
    }

    const masterEvent = lastEventFor('master')
    const sub1Event = lastEventFor('sub-agent-1')
    const sub2Event = lastEventFor('sub-agent-2')

    return [
      {
        id: 'master',
        name: 'Master Orchestrator',
        role: 'master',
        status: masterEvent ? 'working' : 'idle',
        currentTask: masterEvent?.message || null,
      },
      {
        id: 'sub-agent-1',
        name: 'Sub-Agent 1 — Smart Connector',
        role: 'sub',
        status: sub1Event ? 'working' : 'idle',
        currentTask: sub1Event?.message || null,
      },
      {
        id: 'sub-agent-2',
        name: 'Sub-Agent 2 — Enrichment Specialist',
        role: 'sub',
        status: sub2Event ? 'working' : 'idle',
        currentTask: sub2Event?.message || null,
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
    const lastErrorAt =
      errorEventsToday.length > 0
        ? new Date(
            errorEventsToday[errorEventsToday.length - 1].timestamp
          ).toLocaleTimeString()
        : '—'

    return {
      activeAgents: activeRuns > 0 ? 3 : 0,   // 1 master + 2 sub-agents
      activeMasters: activeRuns > 0 ? 1 : 0,
      activeSubs: activeRuns > 0 ? 2 : 0,
      tasksInFlight: activeRuns,
      tasksQueued: queuedRuns,
      completedToday: completedTodayRuns.length,
      avgDuration,
      errorsToday: errorEventsToday.length,
      lastErrorAt,
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

  return (
    <div className="agents-page-wrapper">
      <Topbar />
      <div className="agents-layout">
        <Sidebar />
        <main className="agents-main">
          <div className="agents-header">
            <h1>Agents</h1>
            <p className="agents-subtitle">
              Live trace of master agent and sub-agent communication
            </p>
          </div>

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
            <div className="agent-stat-card">
              <div className="agent-stat-value error">{stats.errorsToday ?? '—'}</div>
              <div className="agent-stat-label">Errors (today)</div>
              <div className="agent-stat-sub">
                Last error: {stats.lastErrorAt ?? '—'}
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

                  <button className="trace-btn" onClick={handleClearTrace} title="Clear trace">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <polyline points="3 6 5 6 21 6"></polyline>
                      <path d="M19 6l-2 14a2 2 0 0 1-2 2H9a2 2 0 0 1-2-2L5 6"></path>
                    </svg>
                  </button>
                </div>
              </div>

              <div className="trace-stream">
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
