import React, { useState, useEffect } from 'react'
import Topbar from '../components/Topbar'
import Sidebar from '../components/Sidebar'
import '../styles/Activity.css'
import { supabase } from '../lib/supabase'

export default function Activity() {
  const [searchTerm, setSearchTerm] = useState('')
  const [activityData, setActivityData] = useState([])
  const [activityStats, setActivityStats] = useState({ events24h: { total: 0, scan: 0, risk: 0, fix: 0, validation: 0 }, ticketsOpened: { total: 0, inProgress: 0, closed: 0 }, validations: { total: 0, pass: 0, fail: 0 } })
  const [mostActiveEntities, setMostActiveEntities] = useState([])
  const [, setLoading] = useState(true)

  useEffect(() => {
    async function loadActivity() {
      try {
        // Pull recent trace events (same as Agents page) + tickets
        const [tracesRes, ticketsRes] = await Promise.all([
          supabase
            .from('agent_trace_events')
            .select('*')
            .order('created_at', { ascending: false })
            .limit(50),
          supabase
            .from('tickets')
            .select('id, status, created_at, external_ticket_id')
            .not('external_ticket_id', 'is', null)
        ])

        const traces = tracesRes.data || []
        const ticketsData = ticketsRes.data || []

        // Map trace events to activity feed format
        const mapped = traces.map((row) => {
          const payload = row.payload || {}
          const eventType = row.event_type || ''
          let event = row.message || eventType.replace(/_/g, ' ')
          let entity = payload.scanner || payload.sub_agent_id || row.agent || ''
          let source = row.agent || ''
          let severity = null
          let status = 'Logged'
          let detail = ''

          if (eventType === 'DISPATCH') { status = 'In Progress'; detail = payload.sub_agent_id ? `→ ${payload.sub_agent_id}` : '' }
          else if (eventType === 'DONE') { status = 'Validated'; detail = payload.summary || '' }
          else if (eventType === 'MESSAGE') { status = 'Logged'; detail = (row.message || '').slice(0, 80) }
          else if (eventType === 'ERROR') { status = 'Failed'; severity = 'High'; detail = payload.error || row.message || '' }

          return {
            id: row.id,
            time: new Date(row.created_at).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }),
            event: event.slice(0, 60),
            entity,
            detail: detail.slice(0, 80),
            source,
            severity,
            status,
          }
        })

        setActivityData(mapped)

        // Compute stats from last 24h
        const now = new Date()
        const h24 = new Date(now - 24 * 60 * 60 * 1000)
        const recent = traces.filter(t => new Date(t.created_at) > h24)
        const scanEvents = recent.filter(t => (t.event_type || '') === 'DISPATCH')
        const riskEvents = recent.filter(t => (t.message || '').toLowerCase().includes('enrich'))
        const fixEvents = recent.filter(t => (t.message || '').toLowerCase().includes('remediat') || (t.message || '').toLowerCase().includes('fix'))
        const valEvents = recent.filter(t => (t.event_type || '') === 'DONE')

        // Tickets stats
        const totalTickets = ticketsData.length
        const closedTickets = ticketsData.filter(t => t.status === 'closed').length
        const inProgressTickets = totalTickets - closedTickets

        setActivityStats({
          events24h: { total: recent.length, scan: scanEvents.length, risk: riskEvents.length, fix: fixEvents.length, validation: valEvents.length },
          ticketsOpened: { total: totalTickets, inProgress: inProgressTickets, closed: closedTickets },
          validations: { total: valEvents.length, pass: valEvents.length, fail: recent.filter(t => (t.event_type || '') === 'ERROR').length },
        })

        // Most active entities — group by agent
        const agentCounts = {}
        for (const t of traces) {
          const key = t.agent || 'unknown'
          agentCounts[key] = (agentCounts[key] || 0) + 1
        }
        setMostActiveEntities(
          Object.entries(agentCounts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5)
            .map(([name, events]) => ({ name, events }))
        )
      } catch (e) {
        console.error('Activity load error:', e)
      } finally {
        setLoading(false)
      }
    }

    loadActivity()
  }, [])

  const filteredActivity = activityData.filter(item =>
    searchTerm === '' ||
    item.event.toLowerCase().includes(searchTerm.toLowerCase()) ||
    item.entity.toLowerCase().includes(searchTerm.toLowerCase()) ||
    item.source.toLowerCase().includes(searchTerm.toLowerCase())
  )

  const getStatusClass = (status) => {
    const statusMap = {
      'Logged': 'logged',
      'Action Needed': 'action-needed',
      'Draft': 'draft',
      'In Progress': 'in-progress',
      'Validated': 'validated',
      'Pending': 'pending',
      'Approved': 'approved',
      'Failed': 'failed'
    }
    return statusMap[status] || 'default'
  }

  const getSeverityClass = (severity) => {
    if (!severity) return ''
    return severity.toLowerCase()
  }

  return (
    <div className="activity-page-wrapper">
      <Topbar />
      <div className="activity-layout">
        <Sidebar />
        <main className="activity-main">
          <div className="activity-header">
            <h1>Activity</h1>
            <p className="activity-subtitle">View system activity and audit trail across your organization</p>
          </div>

          {/* Stats Cards */}
          <div className="activity-stats-row">
            <div className="stat-card">
              <div className="stat-value">{activityStats.events24h?.total}</div>
              <div className="stat-label">Events (24h)</div>
              <div className="stat-breakdown">
                Scan: {activityStats.events24h?.scan} | Risk: {activityStats.events24h?.risk} | Fix: {activityStats.events24h?.fix} | Validation: {activityStats.events24h?.validation}
              </div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{activityStats.ticketsOpened?.total}</div>
              <div className="stat-label">Tickets Opened</div>
              <div className="stat-breakdown">
                In progress: {activityStats.ticketsOpened?.inProgress} | Closed: {activityStats.ticketsOpened?.closed}
              </div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{activityStats.validations?.total}</div>
              <div className="stat-label">Validations</div>
              <div className="stat-breakdown">
                <span className="pass">Pass: {activityStats.validations?.pass}</span> | <span className="fail">Fail: {activityStats.validations?.fail}</span>
              </div>
            </div>
          </div>

          <div className="activity-content-grid">
            {/* Main Activity Table */}
            <div className="activity-card main-card">
              <div className="card-header">
                <h2>Activity Feed</h2>
                <div className="card-toolbar">
                  <div className="activity-search">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <circle cx="11" cy="11" r="8"></circle>
                      <path d="m21 21-4.35-4.35"></path>
                    </svg>
                    <input
                      type="text"
                      placeholder="Search by asset, CVE, issue ID, ticket, or user..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                    />
                  </div>
                  <button className="filter-btn">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"></polygon>
                    </svg>
                  </button>
                </div>
              </div>

              <div className="activity-table-container">
                <table className="activity-table">
                  <thead>
                    <tr>
                      <th>TIME</th>
                      <th>EVENT</th>
                      <th>ENTITY</th>
                      <th>SOURCE</th>
                      <th>SEVERITY</th>
                      <th>STATUS</th>
                      <th>ACTION</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredActivity.map((item) => (
                      <tr key={item.id}>
                        <td className="time-cell">{item.time}</td>
                        <td className="event-cell">{item.event}</td>
                        <td className="entity-cell">
                          <span className="entity-name">{item.entity}</span>
                          {item.detail && <span className="entity-detail">{item.detail}</span>}
                        </td>
                        <td className="source-cell">{item.source}</td>
                        <td>
                          {item.severity && (
                            <span className={`severity-badge ${getSeverityClass(item.severity)}`}>
                              {item.severity}
                            </span>
                          )}
                        </td>
                        <td>
                          <span className={`status-badge ${getStatusClass(item.status)}`}>
                            {item.status}
                          </span>
                        </td>
                        <td>
                          <button className="action-btn">
                            {item.status === 'Validated' || item.status === 'Failed' ? 'Evidence' :
                             item.status === 'Pending' ? 'Review' : 'View'}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Most Active Entities */}
            <div className="activity-card side-card">
              <div className="card-header">
                <h2>Most Active Entities</h2>
              </div>
              <div className="entities-list">
                {mostActiveEntities.map((entity, index) => (
                  <div key={index} className="entity-item">
                    <div className="entity-rank">{index + 1}</div>
                    <span className="entity-asset-name">{entity.name}</span>
                    <span className="entity-count">{entity.events} events</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  )
}
