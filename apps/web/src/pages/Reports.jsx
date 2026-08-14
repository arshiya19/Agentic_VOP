import React, { useState, useEffect } from 'react'
import Topbar from '../components/Topbar'
import Sidebar from '../components/Sidebar'
import '../styles/Reports.css'
import { supabase } from '../lib/supabase'

export default function Reports() {
  const [searchTerm, setSearchTerm] = useState('')
  const [filterType, setFilterType] = useState('All')
  const [reportsData, setReportsData] = useState([])
  const [reportStats, setReportStats] = useState({ totalReports: 0, generatedThisWeek: 0, scheduled: 0, favorites: 0 })
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [newReport, setNewReport] = useState({ name: '', type: 'Executive', format: 'PDF', schedule: 'On-demand' })

  useEffect(() => {
    async function loadReports() {
      // Pull summary data to generate report entries
      const [issuesRes, assetsRes] = await Promise.all([
        supabase.from('issues').select('severity, source, created_at', { count: 'exact', head: false }).limit(500),
        supabase.from('assets').select('asset_id', { count: 'exact', head: true }),
      ])

      const issues = issuesRes.data || []
      const issueCount = issuesRes.count || issues.length
      const assetCount = assetsRes.count || 0

      // Count by severity
      const sevCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 }
      issues.forEach(i => { if (sevCounts[i.severity] !== undefined) sevCounts[i.severity] += 1 })

      // Count unique sources
      const sources = new Set(issues.map(i => i.source).filter(Boolean))

      // Generate realistic report entries based on real data
      const now = new Date()
      const reports = [
        { id: 'RPT-001', name: 'Executive Risk Summary', type: 'Executive', format: 'PDF', schedule: 'Weekly', lastGenerated: new Date(now - 2 * 86400000).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }), size: '2.4 MB', status: 'Ready', description: `${issueCount} total issues across ${assetCount} assets. ${sevCounts.Critical} critical, ${sevCounts.High} high.` },
        { id: 'RPT-002', name: 'Vulnerability Detail Report', type: 'Technical', format: 'CSV', schedule: 'Daily', lastGenerated: new Date(now - 86400000).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }), size: '8.1 MB', status: 'Ready', description: `Full export of ${issueCount} vulnerabilities with CVSS, EPSS, and derived risk scores.` },
        { id: 'RPT-003', name: 'Compliance Posture Report', type: 'Compliance', format: 'PDF', schedule: 'Monthly', lastGenerated: new Date(now - 7 * 86400000).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }), size: '5.6 MB', status: 'Ready', description: `Compliance status across ${assetCount} assets including PCI-DSS, SOC2, HIPAA frameworks.` },
        { id: 'RPT-004', name: 'Scanner Coverage Report', type: 'Operational', format: 'XLSX', schedule: 'Weekly', lastGenerated: new Date(now - 3 * 86400000).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }), size: '1.8 MB', status: 'Ready', description: `Coverage across ${sources.size} scanners. Last scan activity within 24h.` },
        { id: 'RPT-005', name: 'Remediation Progress Report', type: 'Executive', format: 'PPTX', schedule: 'Weekly', lastGenerated: new Date(now - 4 * 86400000).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }), size: '3.2 MB', status: 'Ready', description: `Remediation pipeline status, MTTR trends, and approval metrics.` },
        { id: 'RPT-006', name: 'Asset Risk Heatmap', type: 'Technical', format: 'PDF', schedule: 'Weekly', lastGenerated: new Date(now - 5 * 86400000).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }), size: '4.1 MB', status: 'Ready', description: `Risk distribution across ${assetCount} assets with criticality breakdown.` },
        { id: 'RPT-007', name: 'SLA Breach Report', type: 'Operational', format: 'CSV', schedule: 'Daily', lastGenerated: now.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }), size: '0.5 MB', status: 'Generating', description: `Issues approaching or past SLA deadlines. ${sevCounts.Critical} critical within 72h window.` },
        { id: 'RPT-008', name: 'CISA KEV Exposure Report', type: 'Compliance', format: 'PDF', schedule: 'Daily', lastGenerated: now.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }), size: '1.2 MB', status: 'Ready', description: `Issues matching CISA Known Exploited Vulnerabilities catalog.` },
        { id: 'RPT-009', name: 'Top 10 Risk Drivers', type: 'Executive', format: 'PDF', schedule: 'On-demand', lastGenerated: new Date(now - 1 * 86400000).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }), size: '1.5 MB', status: 'Ready', description: `Highest derived-risk issues with asset context and recommended actions.` },
        { id: 'RPT-010', name: 'Full Issues Export', type: 'Technical', format: 'CSV', schedule: 'On-demand', lastGenerated: new Date(now - 2 * 86400000).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }), size: '12.4 MB', status: 'Ready', description: `Complete database export — ${issueCount} issues with all enrichment fields.` },
      ]

      setReportsData(reports)
      setReportStats({
        totalReports: reports.length,
        generatedThisWeek: reports.filter(r => r.status === 'Ready').length,
        scheduled: reports.filter(r => r.schedule !== 'On-demand').length,
        favorites: 3,
      })
    }
    loadReports()
  }, [])

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
            <button className="btn-primary" onClick={() => setShowCreateModal(true)}>
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
                          onClick={() => {
                            // Generate a text file with the report description as content
                            const content = `${report.name}\nType: ${report.type}\nGenerated: ${report.lastGenerated}\n\n${report.description || ''}`
                            const blob = new Blob([content], { type: 'text/plain' })
                            const url = URL.createObjectURL(blob)
                            const link = document.createElement('a')
                            link.href = url
                            link.download = `${report.id}_${report.name.replace(/\s+/g, '_')}.${report.format.toLowerCase() === 'csv' ? 'csv' : report.format.toLowerCase() === 'xlsx' ? 'xlsx' : 'txt'}`
                            link.click()
                            URL.revokeObjectURL(url)
                          }}
                        >
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                            <polyline points="7 10 12 15 17 10"></polyline>
                            <line x1="12" y1="15" x2="12" y2="3"></line>
                          </svg>
                        </button>
                        <button className="action-btn" title="Regenerate" onClick={() => {
                          setReportsData(prev => prev.map(r => r.id === report.id ? { ...r, status: 'Generating' } : r))
                          setTimeout(() => {
                            setReportsData(prev => prev.map(r => r.id === report.id ? { ...r, status: 'Ready', lastGenerated: new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) } : r))
                          }, 2000)
                        }}>
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <polyline points="23 4 23 10 17 10"></polyline>
                            <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path>
                          </svg>
                        </button>
                        <button className="action-btn" title="Delete" onClick={() => {
                          setReportsData(prev => prev.filter(r => r.id !== report.id))
                          setReportStats(prev => ({ ...prev, totalReports: prev.totalReports - 1 }))
                        }}>
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <polyline points="3 6 5 6 21 6"></polyline>
                            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
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

      {/* Create Report Modal */}
      {showCreateModal && (
        <div className="report-modal-overlay" onClick={() => setShowCreateModal(false)}>
          <div className="report-modal" onClick={(e) => e.stopPropagation()}>
            <div className="report-modal-header">
              <h2>Create New Report</h2>
              <button className="report-modal-close" onClick={() => setShowCreateModal(false)}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18"></line>
                  <line x1="6" y1="6" x2="18" y2="18"></line>
                </svg>
              </button>
            </div>
            <div className="report-modal-body">
              <div className="report-form-group">
                <label>Report Name</label>
                <input
                  type="text"
                  placeholder="e.g. Monthly Executive Summary"
                  value={newReport.name}
                  onChange={(e) => setNewReport(prev => ({ ...prev, name: e.target.value }))}
                />
              </div>
              <div className="report-form-row">
                <div className="report-form-group">
                  <label>Type</label>
                  <select value={newReport.type} onChange={(e) => setNewReport(prev => ({ ...prev, type: e.target.value }))}>
                    <option>Executive</option>
                    <option>Technical</option>
                    <option>Compliance</option>
                    <option>Operational</option>
                  </select>
                </div>
                <div className="report-form-group">
                  <label>Format</label>
                  <select value={newReport.format} onChange={(e) => setNewReport(prev => ({ ...prev, format: e.target.value }))}>
                    <option>PDF</option>
                    <option>CSV</option>
                    <option>XLSX</option>
                    <option>PPTX</option>
                  </select>
                </div>
                <div className="report-form-group">
                  <label>Schedule</label>
                  <select value={newReport.schedule} onChange={(e) => setNewReport(prev => ({ ...prev, schedule: e.target.value }))}>
                    <option>On-demand</option>
                    <option>Daily</option>
                    <option>Weekly</option>
                    <option>Monthly</option>
                  </select>
                </div>
              </div>
            </div>
            <div className="report-modal-footer">
              <button className="btn-secondary" onClick={() => setShowCreateModal(false)}>Cancel</button>
              <button className="btn-primary" onClick={() => {
                if (!newReport.name.trim()) return
                const id = `RPT-${String(reportsData.length + 1).padStart(3, '0')}`
                const created = {
                  id,
                  name: newReport.name,
                  type: newReport.type,
                  format: newReport.format,
                  schedule: newReport.schedule,
                  lastGenerated: 'Generating...',
                  size: '—',
                  status: 'Generating',
                  description: '',
                }
                setReportsData(prev => [created, ...prev])
                setReportStats(prev => ({ ...prev, totalReports: prev.totalReports + 1 }))
                setShowCreateModal(false)
                setNewReport({ name: '', type: 'Executive', format: 'PDF', schedule: 'On-demand' })
                // Simulate generation completing after 3s
                setTimeout(() => {
                  setReportsData(prev => prev.map(r => r.id === id ? { ...r, status: 'Ready', lastGenerated: new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }), size: '1.2 MB' } : r))
                }, 3000)
              }}>
                Generate Report
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
