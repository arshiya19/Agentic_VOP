import React, { useState } from 'react'
import Topbar from '../components/Topbar'
import Sidebar from '../components/Sidebar'
import '../styles/Reports.css'

export default function Reports() {
  const [searchTerm, setSearchTerm] = useState('')
  const [filterType, setFilterType] = useState('All')
  const [reportsData] = useState([])
  const [reportStats] = useState({})

  const types = ['All', 'Executive', 'Technical', 'Compliance', 'Operational']

  const filteredReports = reportsData.filter(report => {
    const matchesSearch = searchTerm === '' ||
      report.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      report.type.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesType = filterType === 'All' || report.type === filterType
    return matchesSearch && matchesType
  })

  const getStatusClass = (status) => {
    return status.toLowerCase().replace(' ', '-')
  }

  const getFormatIcon = (format) => {
    switch (format) {
      case 'PDF':
        return (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
            <polyline points="14 2 14 8 20 8"></polyline>
          </svg>
        )
      case 'XLSX':
      case 'CSV':
        return (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect>
            <line x1="3" y1="9" x2="21" y2="9"></line>
            <line x1="3" y1="15" x2="21" y2="15"></line>
            <line x1="9" y1="3" x2="9" y2="21"></line>
            <line x1="15" y1="3" x2="15" y2="21"></line>
          </svg>
        )
      case 'PPTX':
        return (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect>
            <line x1="8" y1="21" x2="16" y2="21"></line>
            <line x1="12" y1="17" x2="12" y2="21"></line>
          </svg>
        )
      default:
        return null
    }
  }

  return (
    <div className="reports-page-wrapper">
      <Topbar />
      <div className="reports-layout">
        <Sidebar />
        <main className="reports-main">
          <div className="reports-header">
            <div className="reports-header-left">
              <h1>Reports</h1>
              <p className="reports-subtitle">Generate, schedule, and download security reports</p>
            </div>
            <button className="btn-primary">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <line x1="12" y1="5" x2="12" y2="19"></line>
                <line x1="5" y1="12" x2="19" y2="12"></line>
              </svg>
              Create Report
            </button>
          </div>

          {/* Stats Cards */}
          <div className="reports-stats-row">
            <div className="stat-card">
              <div className="stat-value">{reportStats.totalReports}</div>
              <div className="stat-label">Total Reports</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{reportStats.generatedThisWeek}</div>
              <div className="stat-label">Generated This Week</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{reportStats.scheduled}</div>
              <div className="stat-label">Scheduled</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{reportStats.favorites}</div>
              <div className="stat-label">Favorites</div>
            </div>
          </div>

          {/* Reports Table */}
          <div className="reports-card">
            <div className="card-header">
              <h2>Recent Reports</h2>
              <div className="card-toolbar">
                <div className="reports-search">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <circle cx="11" cy="11" r="8"></circle>
                    <path d="m21 21-4.35-4.35"></path>
                  </svg>
                  <input
                    type="text"
                    placeholder="Search reports..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                  />
                </div>
                <div className="type-filters">
                  {types.map((type) => (
                    <button
                      key={type}
                      className={`filter-chip ${filterType === type ? 'active' : ''}`}
                      onClick={() => setFilterType(type)}
                    >
                      {type}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            <div className="reports-table-container">
              <table className="reports-table">
                <thead>
                  <tr>
                    <th>REPORT NAME</th>
                    <th>TYPE</th>
                    <th>FORMAT</th>
                    <th>SCHEDULE</th>
                    <th>LAST GENERATED</th>
                    <th>SIZE</th>
                    <th>STATUS</th>
                    <th>ACTIONS</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredReports.map((report) => (
                    <tr key={report.id}>
                      <td className="report-name-cell">
                        <span className="report-name">{report.name}</span>
                        <span className="report-id">{report.id}</span>
                      </td>
                      <td>
                        <span className={`type-badge ${report.type.toLowerCase()}`}>
                          {report.type}
                        </span>
                      </td>
                      <td className="format-cell">
                        {getFormatIcon(report.format)}
                        <span>{report.format}</span>
                      </td>
                      <td className="schedule-cell">{report.schedule}</td>
                      <td className="date-cell">{report.lastGenerated}</td>
                      <td className="size-cell">{report.size}</td>
                      <td>
                        <span className={`status-badge ${getStatusClass(report.status)}`}>
                          {report.status}
                        </span>
                      </td>
                      <td className="actions-cell">
                        <button
                          className="action-btn download"
                          disabled={report.status !== 'Ready'}
                          title="Download"
                        >
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                            <polyline points="7 10 12 15 17 10"></polyline>
                            <line x1="12" y1="15" x2="12" y2="3"></line>
                          </svg>
                        </button>
                        <button className="action-btn" title="Regenerate">
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <polyline points="23 4 23 10 17 10"></polyline>
                            <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path>
                          </svg>
                        </button>
                        <button className="action-btn" title="More Options">
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <circle cx="12" cy="12" r="1"></circle>
                            <circle cx="19" cy="12" r="1"></circle>
                            <circle cx="5" cy="12" r="1"></circle>
                          </svg>
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </main>
      </div>
    </div>
  )
}
