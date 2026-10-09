import React, { useState } from 'react'
import Topbar from '../components/Topbar'
import Sidebar from '../components/Sidebar'
import '../styles/Alerts.css'

export default function Alerts() {
  const [searchTerm, setSearchTerm] = useState('')
  const [filterSeverity, setFilterSeverity] = useState('All')
  const [filterStatus, setFilterStatus] = useState('All')
  const [alertsData] = useState([])
  const [alertStats] = useState({})
  const [alertCategories] = useState([])

  const severities = ['All', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
  const statuses = ['All', 'New', 'Acknowledged', 'Resolved']

  const filteredAlerts = alertsData.filter(alert => {
    const matchesSearch = searchTerm === '' ||
      alert.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.asset.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.category.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesSeverity = filterSeverity === 'All' || alert.severity === filterSeverity
    const matchesStatus = filterStatus === 'All' || alert.status === filterStatus
    return matchesSearch && matchesSeverity && matchesStatus
  })

  const getSeverityClass = (severity) => {
    return severity.toLowerCase()
  }

  const getStatusClass = (status) => {
    return status.toLowerCase()
  }

  const getCategoryIcon = (category) => {
    switch (category) {
      case 'Vulnerability':
        return (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
            <line x1="12" y1="8" x2="12" y2="12"></line>
            <line x1="12" y1="16" x2="12.01" y2="16"></line>
          </svg>
        )
      case 'SLA':
        return (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="12" r="10"></circle>
            <polyline points="12 6 12 12 16 14"></polyline>
          </svg>
        )
      case 'Validation':
        return (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
            <polyline points="22 4 12 14.01 9 11.01"></polyline>
          </svg>
        )
      case 'Compliance':
        return (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
            <polyline points="14 2 14 8 20 8"></polyline>
            <line x1="16" y1="13" x2="8" y2="13"></line>
            <line x1="16" y1="17" x2="8" y2="17"></line>
          </svg>
        )
      default:
        return (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="12" r="10"></circle>
            <line x1="12" y1="16" x2="12" y2="12"></line>
            <line x1="12" y1="8" x2="12.01" y2="8"></line>
          </svg>
        )
    }
  }

  return (
    <div className="alerts-page-wrapper">
      <Topbar />
      <div className="alerts-layout">
        <Sidebar />
        <main className="alerts-main">
          <div className="alerts-header">
            <div className="alerts-header-left">
              <h1>Alerts</h1>
              <p className="alerts-subtitle">Monitor and manage security alerts across your infrastructure</p>
            </div>
            <div className="alerts-header-actions">
              <button className="btn-secondary">
                Mark All Read
              </button>
              <button className="btn-primary">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="3"></circle>
                  <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
                </svg>
                Settings
              </button>
            </div>
          </div>

          {/* Stats Cards */}
          <div className="alerts-stats-row">
            <div className="stat-card total">
              <div className="stat-value">{alertStats.total}</div>
              <div className="stat-label">Total Alerts</div>
            </div>
            <div className="stat-card critical">
              <div className="stat-value">{alertStats.critical}</div>
              <div className="stat-label">Critical</div>
            </div>
            <div className="stat-card high">
              <div className="stat-value">{alertStats.high}</div>
              <div className="stat-label">High</div>
            </div>
            <div className="stat-card medium">
              <div className="stat-value">{alertStats.medium}</div>
              <div className="stat-label">Medium</div>
            </div>
            <div className="stat-card low">
              <div className="stat-value">{alertStats.low}</div>
              <div className="stat-label">Low</div>
            </div>
          </div>

          <div className="alerts-content-grid">
            {/* Alerts List */}
            <div className="alerts-card main-card">
              <div className="card-header">
                <h2>All Alerts</h2>
                <div className="card-toolbar">
                  <div className="alerts-search">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <circle cx="11" cy="11" r="8"></circle>
                      <path d="m21 21-4.35-4.35"></path>
                    </svg>
                    <input
                      type="text"
                      placeholder="Search alerts..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                    />
                  </div>
                  <select
                    className="filter-select"
                    value={filterSeverity}
                    onChange={(e) => setFilterSeverity(e.target.value)}
                  >
                    {severities.map(s => (
                      <option key={s} value={s}>{s === 'All' ? 'All Severities' : s}</option>
                    ))}
                  </select>
                  <select
                    className="filter-select"
                    value={filterStatus}
                    onChange={(e) => setFilterStatus(e.target.value)}
                  >
                    {statuses.map(s => (
                      <option key={s} value={s}>{s === 'All' ? 'All Statuses' : s}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="alerts-list">
                {filteredAlerts.map((alert) => (
                  <div key={alert.id} className={`alert-item ${alert.status === 'New' ? 'unread' : ''}`}>
                    <div className={`alert-severity-indicator ${getSeverityClass(alert.severity)}`}></div>
                    <div className="alert-icon">
                      {getCategoryIcon(alert.category)}
                    </div>
                    <div className="alert-content">
                      <div className="alert-header-row">
                        <h3 className="alert-title">{alert.title}</h3>
                        <span className="alert-time">{alert.time}</span>
                      </div>
                      <p className="alert-description">{alert.description}</p>
                      <div className="alert-meta">
                        <span className="alert-asset">
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect>
                            <rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect>
                            <line x1="6" y1="6" x2="6.01" y2="6"></line>
                            <line x1="6" y1="18" x2="6.01" y2="18"></line>
                          </svg>
                          {alert.asset}
                        </span>
                        <span className={`alert-category ${alert.category.toLowerCase()}`}>
                          {alert.category}
                        </span>
                        <span className={`alert-status ${getStatusClass(alert.status)}`}>
                          {alert.status}
                        </span>
                      </div>
                    </div>
                    <div className="alert-actions">
                      {alert.status === 'New' && (
                        <button className="action-btn" title="Acknowledge">
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <polyline points="20 6 9 17 4 12"></polyline>
                          </svg>
                        </button>
                      )}
                      <button className="action-btn" title="View Details">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                          <circle cx="12" cy="12" r="3"></circle>
                        </svg>
                      </button>
                      <button className="action-btn" title="More Options">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <circle cx="12" cy="12" r="1"></circle>
                          <circle cx="19" cy="12" r="1"></circle>
                          <circle cx="5" cy="12" r="1"></circle>
                        </svg>
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Categories Sidebar */}
            <div className="alerts-card side-card">
              <div className="card-header">
                <h2>Categories</h2>
              </div>
              <div className="categories-list">
                {alertCategories.map((category, index) => (
                  <div
                    key={index}
                    className="category-item"
                    onClick={() => setSearchTerm(category.name)}
                  >
                    <div
                      className="category-color"
                      style={{ backgroundColor: category.color }}
                    ></div>
                    <span className="category-name">{category.name}</span>
                    <span className="category-count">{category.count}</span>
                  </div>
                ))}
              </div>

              <div className="status-summary">
                <h3>Status Summary</h3>
                <div className="status-item">
                  <span className="status-dot new"></span>
                  <span className="status-name">New</span>
                  <span className="status-count">{alertStats.newAlerts}</span>
                </div>
                <div className="status-item">
                  <span className="status-dot acknowledged"></span>
                  <span className="status-name">Acknowledged</span>
                  <span className="status-count">{alertStats.acknowledged}</span>
                </div>
                <div className="status-item">
                  <span className="status-dot resolved"></span>
                  <span className="status-name">Resolved</span>
                  <span className="status-count">{alertStats.resolved}</span>
                </div>
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  )
}
