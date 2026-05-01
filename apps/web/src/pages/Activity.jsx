import React, { useState } from 'react'
import Topbar from '../components/Topbar'
import Sidebar from '../components/Sidebar'
import '../styles/Activity.css'

export default function Activity() {
  const [searchTerm, setSearchTerm] = useState('')
  const [activityData] = useState([])
  const [activityStats] = useState({})
  const [mostActiveEntities] = useState([])

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
