import { useState } from 'react'
import Topbar from '../components/Topbar'
import Sidebar from '../components/Sidebar'
import '../App.css'

export default function AdminDashboard() {
  const [stats] = useState({
    totalUsers: 0,
    totalVulnerabilities: 0,
    criticalVulns: 0,
    highVulns: 0,
  })
  const [recentActivity] = useState([])

  const getSeverityClass = (severity) => {
    if (!severity) return 'low'
    return severity.toLowerCase()
  }

  return (
    <>
      <Topbar />
      <div className="app-layout">
        <Sidebar />
        <main className="dashboard-main">
          <div className="dashboard-header">
            <h1>Admin Dashboard</h1>
            <p className="dashboard-subtitle">System overview and management</p>
          </div>

          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-info">
                <div className="stat-count">{stats.totalUsers}</div>
                <div className="stat-label">Total Users</div>
              </div>
            </div>

            <div className="stat-card">
              <div className="stat-info">
                <div className="stat-count">{stats.totalVulnerabilities}</div>
                <div className="stat-label">Total Vulnerabilities</div>
              </div>
            </div>

            <div className="stat-card">
              <div className="stat-info">
                <div className="stat-count">{stats.criticalVulns}</div>
                <div className="stat-label">Critical</div>
              </div>
            </div>

            <div className="stat-card">
              <div className="stat-info">
                <div className="stat-count">{stats.highVulns}</div>
                <div className="stat-label">High Severity</div>
              </div>
            </div>
          </div>

          <div className="dashboard-section" style={{ marginTop: '2rem' }}>
            <h2 style={{ marginBottom: '1.5rem' }}>Recent Vulnerabilities</h2>

            {recentActivity.length === 0 ? (
              <p style={{ color: 'var(--text-secondary)' }}>No recent activity</p>
            ) : (
              <div className="vuln-list">
                {recentActivity.map((vuln) => (
                  <div key={vuln.id} className="vuln-item">
                    <span className={`vuln-severity ${getSeverityClass(vuln.cvss_base_severity)}`}>
                      {vuln.cvss_base_severity || 'UNKNOWN'}
                    </span>
                    <span className="vuln-title">
                      {vuln.cve_id} - {vuln.description?.substring(0, 80) || 'No description'}...
                    </span>
                    <span className="vuln-date">
                      {new Date(vuln.created_at).toLocaleDateString()}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </main>
      </div>
    </>
  )
}