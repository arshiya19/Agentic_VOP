import { useState } from 'react'
import Topbar from '../components/Topbar'
import Sidebar from '../components/Sidebar'
import '../App.css'

export default function SystemSettings() {
  const [siteName, setSiteName] = useState('CyberRisk AI')
  const [maintenanceMode, setMaintenanceMode] = useState(false)
  const [emailNotifications, setEmailNotifications] = useState(true)
  const [autoScan, setAutoScan] = useState(false)
  const [scanFrequency, setScanFrequency] = useState('24')
  const [maxScans, setMaxScans] = useState('5')

  // Wire to backend when ready.
  const handleSave = () => {}

  return (
    <>
      <Topbar />
      <div className="app-layout">
        <Sidebar />
        <main className="dashboard-main">
          <div className="dashboard-header">
            <h1>System Settings</h1>
            <p className="dashboard-subtitle">Configure system-wide settings and preferences</p>
          </div>

          <div className="settings-container">
            {/* General Settings */}
            <div className="settings-section">
              <h2>General Settings</h2>
              <div className="settings-grid">
                <div className="settings-item">
                  <label className="settings-label">Site Name</label>
                  <input
                    type="text"
                    className="settings-input"
                    value={siteName}
                    onChange={(e) => setSiteName(e.target.value)}
                    placeholder="CyberRisk AI"
                  />
                </div>
                <div className="settings-item">
                  <label className="settings-label">API Endpoint</label>
                  <input
                    type="text"
                    className="settings-input"
                    value="http://127.0.0.1:8000"
                    disabled
                  />
                  <p className="settings-help">Backend API endpoint (read-only)</p>
                </div>
              </div>
            </div>

            {/* System Features */}
            <div className="settings-section">
              <h2>System Features</h2>
              <div className="settings-options">
                <label className="settings-checkbox">
                  <input
                    type="checkbox"
                    checked={maintenanceMode}
                    onChange={(e) => setMaintenanceMode(e.target.checked)}
                  />
                  <div className="checkbox-content">
                    <div className="checkbox-title">Enable Maintenance Mode</div>
                    <div className="checkbox-description">
                      Put the system in maintenance mode to prevent user access during updates
                    </div>
                  </div>
                </label>

                <label className="settings-checkbox">
                  <input
                    type="checkbox"
                    checked={emailNotifications}
                    onChange={(e) => setEmailNotifications(e.target.checked)}
                  />
                  <div className="checkbox-content">
                    <div className="checkbox-title">Enable Email Notifications</div>
                    <div className="checkbox-description">
                      Send email notifications for critical vulnerabilities and system alerts
                    </div>
                  </div>
                </label>

                <label className="settings-checkbox">
                  <input
                    type="checkbox"
                    checked={autoScan}
                    onChange={(e) => setAutoScan(e.target.checked)}
                    disabled
                  />
                  <div className="checkbox-content">
                    <div className="checkbox-title">Enable Automatic Vulnerability Scanning</div>
                    <div className="checkbox-description">
                      Automatically scan for vulnerabilities at scheduled intervals (Coming Soon)
                    </div>
                  </div>
                </label>
              </div>
            </div>

            {/* Scan Configuration */}
            <div className="settings-section">
              <h2>Scan Configuration</h2>
              <div className="settings-grid">
                <div className="settings-item">
                  <label className="settings-label">Scan Frequency (hours)</label>
                  <input
                    type="number"
                    className="settings-input"
                    value={scanFrequency}
                    onChange={(e) => setScanFrequency(e.target.value)}
                    min="1"
                    max="168"
                  />
                  <p className="settings-help">How often to run automated scans (1-168 hours)</p>
                </div>
                <div className="settings-item">
                  <label className="settings-label">Max Concurrent Scans</label>
                  <input
                    type="number"
                    className="settings-input"
                    value={maxScans}
                    onChange={(e) => setMaxScans(e.target.value)}
                    min="1"
                    max="20"
                  />
                  <p className="settings-help">Maximum number of scans to run simultaneously (1-20)</p>
                </div>
              </div>
            </div>

            {/* Save Button */}
            <div className="settings-actions">
              <button className="primary" onClick={handleSave}>
                Save All Settings
              </button>
            </div>
          </div>
        </main>
      </div>
    </>
  )
}
