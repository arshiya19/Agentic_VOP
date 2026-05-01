import Topbar from '../components/Topbar'
import Sidebar from '../components/Sidebar'
import '../styles/Reprioritization.css'

export default function VopReprioritization() {
  return (
    <div className="reprioritization-page-wrapper">
      <Topbar />
      <div className="reprioritization-layout">
        <Sidebar />
        <main className="reprioritization-main">
          <div className="reprioritization-header">
            <h1>Reprioritization</h1>
            <p className="reprioritization-subtitle">Review and manage vulnerability priority adjustments based on risk context</p>
          </div>

          <div className="coming-soon-card">
            <div className="coming-soon-content">
              <div className="coming-soon-icon">
                <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                  <polyline points="17 1 21 5 17 9"></polyline>
                  <path d="M3 11V9a4 4 0 0 1 4-4h14"></path>
                  <polyline points="7 23 3 19 7 15"></polyline>
                  <path d="M21 13v2a4 4 0 0 1-4 4H3"></path>
                </svg>
              </div>
              <h2>Coming Soon</h2>
              <p>We're working on something great! The Reprioritization page will be available in an upcoming release.</p>
              <div className="coming-soon-features">
                <div className="feature-item">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <polyline points="9 11 12 14 22 4"></polyline>
                    <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"></path>
                  </svg>
                  <span>Context-aware priority adjustments</span>
                </div>
                <div className="feature-item">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <polyline points="9 11 12 14 22 4"></polyline>
                    <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"></path>
                  </svg>
                  <span>Risk-based scoring engine</span>
                </div>
                <div className="feature-item">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <polyline points="9 11 12 14 22 4"></polyline>
                    <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"></path>
                  </svg>
                  <span>Approval workflow management</span>
                </div>
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  )
}