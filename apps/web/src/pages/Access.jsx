import { useState } from 'react'
import Topbar from '../components/Topbar'
import Sidebar from '../components/Sidebar'

import '../styles/Access.css'

export default function Access() {
  const [settings, setSettings] = useState({
    showCveTicker: true,
    showRemediableCard: true,
    showTrendChart: true,
  })
  const [saving] = useState(false)
  const [message] = useState('')

  function saveSettings() {}

  function handleToggle(key) {
    setSettings(prev => ({
      ...prev,
      [key]: !prev[key]
    }))
  }

  return (
    <>
      <Topbar />
      <div className="app-layout">
        <Sidebar />
        <main className="access-page">
          <div className="access-header">
            <h1>Access & Display Settings</h1>
            <p className="access-subtitle">Control what users see on their dashboard</p>
          </div>

          <div className="access-content">
            {/* Dashboard Visibility Controls */}
            <div className="settings-card">
              <div className="settings-card-header">
                <h2>Dashboard Visibility</h2>
                <p>Toggle which components are visible to users on their dashboard</p>
              </div>

              <div className="settings-list">
                {/* CVE Ticker Toggle */}
                <div className="settings-item">
                  <div className="settings-item-info">
                    <div className="settings-item-icon ticker">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
                      </svg>
                    </div>
                    <div className="settings-item-text">
                      <h3>Latest CVEs Ticker</h3>
                      <p>Show the scrolling CVE ticker banner at the top of the dashboard</p>
                    </div>
                  </div>
                  <label className="toggle-switch">
                    <input
                      type="checkbox"
                      checked={settings.showCveTicker}
                      onChange={() => handleToggle('showCveTicker')}
                    />
                    <span className="toggle-slider"></span>
                  </label>
                </div>

                {/* Remediable Card Toggle */}
                <div className="settings-item">
                  <div className="settings-item-info">
                    <div className="settings-item-icon remediation">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                      </svg>
                    </div>
                    <div className="settings-item-text">
                      <h3>Remediable Vulnerabilities Card</h3>
                      <p>Show the expandable remediation statistics card</p>
                    </div>
                  </div>
                  <label className="toggle-switch">
                    <input
                      type="checkbox"
                      checked={settings.showRemediableCard}
                      onChange={() => handleToggle('showRemediableCard')}
                    />
                    <span className="toggle-slider"></span>
                  </label>
                </div>

                {/* Trend Chart Toggle */}
                <div className="settings-item">
                  <div className="settings-item-info">
                    <div className="settings-item-icon chart">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/>
                        <polyline points="17 6 23 6 23 12"/>
                      </svg>
                    </div>
                    <div className="settings-item-text">
                      <h3>Vulnerability Trends Chart</h3>
                      <p>Show the 6-month vulnerability trends line chart</p>
                    </div>
                  </div>
                  <label className="toggle-switch">
                    <input
                      type="checkbox"
                      checked={settings.showTrendChart}
                      onChange={() => handleToggle('showTrendChart')}
                    />
                    <span className="toggle-slider"></span>
                  </label>
                </div>
              </div>

              <div className="settings-card-footer">
                {message && (
                  <span className={`settings-message ${message.includes('success') ? 'success' : 'error'}`}>
                    {message}
                  </span>
                )}
                <button
                  className="save-settings-btn"
                  onClick={saveSettings}
                  disabled={saving}
                >
                  {saving ? 'Saving...' : 'Save Changes'}
                </button>
              </div>
            </div>

            {/* Future: Role-based Access */}
            <div className="settings-card disabled">
              <div className="settings-card-header">
                <h2>Role-Based Access</h2>
                <p>Configure permissions for different user roles</p>
                <span className="coming-soon-badge">Coming Soon</span>
              </div>
            </div>
          </div>
        </main>
      </div>
    </>
  )
}