import Topbar from '../components/Topbar'
import Sidebar from '../components/Sidebar'
import '../App.css'

export default function Analytics() {
  const analyticsFeatures = [
    {
      title: 'Vulnerability Trends',
      description: 'Track vulnerability trends over time',
      status: 'coming-soon'
    },
    {
      title: 'Risk Scoring',
      description: 'Advanced risk scoring and prioritization',
      status: 'coming-soon'
    },
    {
      title: 'Remediation Tracking',
      description: 'Monitor remediation progress tracking',
      status: 'coming-soon'
    },
    {
      title: 'Asset Analytics',
      description: 'Asset-based analytics and insights',
      status: 'coming-soon'
    },
    {
      title: 'Compliance Dashboard',
      description: 'Exportable reports and dashboards',
      status: 'coming-soon'
    },
    {
      title: 'Threat Intelligence',
      description: 'Real-time threat intelligence feeds',
      status: 'coming-soon'
    },
  ]

  return (
    <>
      <Topbar />
      <div className="app-layout">
        <Sidebar />
        <main className="dashboard-main">
          <div className="dashboard-header">
            <h1>Analytics</h1>
            <p className="dashboard-subtitle">Platform analytics and insights</p>
          </div>

          <div className="reports-grid">
            {analyticsFeatures.map((feature, index) => (
              <div key={index} className="report-card">
                <h3>{feature.title}</h3>
                <p>{feature.description}</p>
                <button className="primary" disabled>
                  Coming Soon
                </button>
              </div>
            ))}
          </div>
        </main>
      </div>
    </>
  )
}
