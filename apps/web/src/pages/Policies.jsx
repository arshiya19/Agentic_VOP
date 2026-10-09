import React, { useState } from 'react'
import Topbar from '../components/Topbar'
import Sidebar from '../components/Sidebar'
import '../styles/Policies.css'

export default function Policies() {
  const [searchTerm, setSearchTerm] = useState('')
  const [filterCategory, setFilterCategory] = useState('All')
  const [filterStatus, setFilterStatus] = useState('All')
  const [policiesData] = useState([])
  const [policyStats] = useState({})
  const [policyCategories] = useState([])

  const categories = ['All', ...policyCategories.map(c => c.name)]
  const statuses = ['All', 'Active', 'Draft']

  const filteredPolicies = policiesData.filter(policy => {
    const matchesSearch = searchTerm === '' ||
      policy.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      policy.description.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesCategory = filterCategory === 'All' || policy.category === filterCategory
    const matchesStatus = filterStatus === 'All' || policy.status === filterStatus
    return matchesSearch && matchesCategory && matchesStatus
  })

  const getSeverityClass = (severity) => {
    if (!severity) return ''
    return severity.toLowerCase()
  }

  const getStatusClass = (status) => {
    return status.toLowerCase()
  }

  return (
    <div className="policies-page-wrapper">
      <Topbar />
      <div className="policies-layout">
        <Sidebar />
        <main className="policies-main">
          <div className="policies-header">
            <div className="policies-header-left">
              <h1>Policies</h1>
              <p className="policies-subtitle">Manage security policies, SLAs, and compliance rules</p>
            </div>
            <button className="btn-primary">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <line x1="12" y1="5" x2="12" y2="19"></line>
                <line x1="5" y1="12" x2="19" y2="12"></line>
              </svg>
              Create Policy
            </button>
          </div>

          {/* Stats Cards */}
          <div className="policies-stats-row">
            <div className="stat-card">
              <div className="stat-value">{policyStats.total}</div>
              <div className="stat-label">Total Policies</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{policyStats.active}</div>
              <div className="stat-label">Active</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{policyStats.draft}</div>
              <div className="stat-label">Draft</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{Object.keys(policyStats.categories ?? {}).length}</div>
              <div className="stat-label">Categories</div>
            </div>
          </div>

          <div className="policies-content-grid">
            {/* Policies Table */}
            <div className="policies-card main-card">
              <div className="card-header">
                <h2>All Policies</h2>
                <div className="card-toolbar">
                  <div className="policies-search">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <circle cx="11" cy="11" r="8"></circle>
                      <path d="m21 21-4.35-4.35"></path>
                    </svg>
                    <input
                      type="text"
                      placeholder="Search policies..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                    />
                  </div>
                  <select
                    className="filter-select"
                    value={filterCategory}
                    onChange={(e) => setFilterCategory(e.target.value)}
                  >
                    {categories.map(c => (
                      <option key={c} value={c}>{c === 'All' ? 'All Categories' : c}</option>
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

              <div className="policies-table-container">
                <table className="policies-table">
                  <thead>
                    <tr>
                      <th>POLICY NAME</th>
                      <th>CATEGORY</th>
                      <th>SEVERITY</th>
                      <th>STATUS</th>
                      <th>APPLIES TO</th>
                      <th>LAST MODIFIED</th>
                      <th>ACTIONS</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredPolicies.map((policy) => (
                      <tr key={policy.id}>
                        <td className="policy-name-cell">
                          <span className="policy-name">{policy.name}</span>
                          <span className="policy-description">{policy.description}</span>
                        </td>
                        <td>
                          <span className="category-badge">{policy.category}</span>
                        </td>
                        <td>
                          {policy.severity ? (
                            <span className={`severity-badge ${getSeverityClass(policy.severity)}`}>
                              {policy.severity}
                            </span>
                          ) : (
                            <span className="severity-na">—</span>
                          )}
                        </td>
                        <td>
                          <span className={`status-badge ${getStatusClass(policy.status)}`}>
                            {policy.status}
                          </span>
                        </td>
                        <td className="applies-to-cell">{policy.appliesTo}</td>
                        <td className="date-cell">
                          <span className="date">{policy.lastModified}</span>
                          <span className="modified-by">by {policy.modifiedBy}</span>
                        </td>
                        <td className="actions-cell">
                          <button className="action-btn" title="Edit">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                              <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
                              <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
                            </svg>
                          </button>
                          <button className="action-btn" title="View">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                              <circle cx="12" cy="12" r="3"></circle>
                            </svg>
                          </button>
                          <button className="action-btn" title="More">
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

            {/* Categories Sidebar */}
            <div className="policies-card side-card">
              <div className="card-header">
                <h2>Categories</h2>
              </div>
              <div className="categories-list">
                {policyCategories.map((category, index) => (
                  <div
                    key={index}
                    className={`category-item ${filterCategory === category.name ? 'active' : ''}`}
                    onClick={() => setFilterCategory(filterCategory === category.name ? 'All' : category.name)}
                  >
                    <div className="category-icon" style={{ backgroundColor: category.color + '20', color: category.color }}>
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                      </svg>
                    </div>
                    <span className="category-name">{category.name}</span>
                    <span className="category-count">{category.count}</span>
                  </div>
                ))}
              </div>

              <div className="quick-actions">
                <h3>Quick Actions</h3>
                <button className="quick-action-btn">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                    <polyline points="17 8 12 3 7 8"></polyline>
                    <line x1="12" y1="3" x2="12" y2="15"></line>
                  </svg>
                  Import Policies
                </button>
                <button className="quick-action-btn">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                    <polyline points="7 10 12 15 17 10"></polyline>
                    <line x1="12" y1="15" x2="12" y2="3"></line>
                  </svg>
                  Export Policies
                </button>
                <button className="quick-action-btn">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect>
                    <line x1="3" y1="9" x2="21" y2="9"></line>
                    <line x1="9" y1="21" x2="9" y2="9"></line>
                  </svg>
                  Policy Templates
                </button>
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  )
}
