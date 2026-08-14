import { useState } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'
import SidebarIcons from './icons/SidebarIcons'

import '../styles/Sidebar.css'

export default function Sidebar() {
  const navigate = useNavigate()
  const location = useLocation()
  const { userRole } = useAuth()
  const [isCollapsed, setIsCollapsed] = useState(false)

  const isActive = (path) => location.pathname === path

  // Toggle collapse/expand
  const toggleCollapse = () => {
    setIsCollapsed(!isCollapsed)
  }

  // Handle menu item click - navigate
  const handleItemClick = (path) => {
    navigate(path)
  }

  // Main menu items - User
  const userMainMenuItems = [
    { path: '/dashboard', label: 'Dashboard', icon: 'Dashboard' },
    { path: '/issues', label: 'Issues', icon: 'Issues' },
    { path: '/assets', label: 'Assets', icon: 'Assets' },
    { path: '/remediation', label: 'Remediation', icon: 'Remediation' },
    { path: '/validation', label: 'Validation', icon: 'Validation' },
    { path: '/integrations', label: 'Integrations', icon: 'IntegrationsCustom' },
    { path: '/agents', label: 'Agents', icon: 'Agents' },
    { path: '/activity', label: 'Activity', icon: 'Activity' },
    { path: '/reports', label: 'Reports', icon: 'Reports' },
    { path: '/alerts', label: 'Alerts', icon: 'Alerts' },
  ]

  const userBottomMenuItems = [
    { path: '/policies', label: 'Policies', icon: 'Policies' },
    { path: '/settings', label: 'Settings', icon: 'Settings' },
  ]

  const adminMainMenuItems = [
    { path: '/admin/agents', label: 'Agents', icon: 'Agents' },
    { path: '/admin/dashboard', label: 'Dashboard', icon: 'Dashboard' },
    { path: '/admin/users', label: 'User Management', icon: 'Users' },
    { path: '/admin/issues', label: 'Issues', icon: 'Issues' },
    { path: '/admin/documents', label: 'Document Manager', icon: 'Documents' },
    { path: '/admin/analytics', label: 'Analytics', icon: 'Analytics' },
    { path: '/admin/remediation', label: 'Remediation', icon: 'Remediation' },
  ]

  const adminBottomMenuItems = [
    { path: '/admin/settings', label: 'System Settings', icon: 'Settings' },
  ]

  const mainMenuItems = userRole === 'admin' ? adminMainMenuItems : userMainMenuItems
  const bottomMenuItems = userRole === 'admin' ? adminBottomMenuItems : userBottomMenuItems

  const renderIcon = (iconName) => {
    if (iconName === 'IntegrationsCustom') {
      return (
        <svg
          width="20"
          height="20"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
        >
          <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path>
          <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path>
        </svg>
      )
    }

    const IconComponent = SidebarIcons[iconName]
    return IconComponent ? <IconComponent /> : null
  }

  return (
    <aside className={`sidebar-nav ${isCollapsed ? 'collapsed' : ''}`}>
      {/* Header with only Collapse Toggle - No Sisy text */}
      <div className="sidebar-toggle-header">
        <button
          className="sidebar-collapse-btn"
          onClick={toggleCollapse}
          title={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {isCollapsed ? (
            // Expand icon (chevron right with panel)
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect>
              <line x1="9" y1="3" x2="9" y2="21"></line>
              <polyline points="14 9 17 12 14 15"></polyline>
            </svg>
          ) : (
            // Collapse icon (chevron left with panel)
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect>
              <line x1="9" y1="3" x2="9" y2="21"></line>
              <polyline points="16 9 13 12 16 15"></polyline>
            </svg>
          )}
        </button>
      </div>

      <nav className="sidebar-menu">
        {/* Main menu */}
        {mainMenuItems.map((item) => (
          <button
            key={item.path}
            className={`sidebar-item ${isActive(item.path) ? 'active' : ''}`}
            onClick={() => handleItemClick(item.path)}
            title={isCollapsed ? item.label : ''}
          >
            <span className="sidebar-icon">
              {renderIcon(item.icon)}
            </span>
            {!isCollapsed && <span className="sidebar-label">{item.label}</span>}
          </button>
        ))}
        <div className="sidebar-spacer"></div>

        {/* Bottom menu */}
        <div className="sidebar-bottom-section">
          {bottomMenuItems.map((item) => (
            <button
              key={item.path}
              className={`sidebar-item sidebar-item-bottom ${isActive(item.path) ? 'active' : ''}`}
              onClick={() => handleItemClick(item.path)}
              title={isCollapsed ? item.label : ''}
            >
              <span className="sidebar-icon">
                {renderIcon(item.icon)}
              </span>
              {!isCollapsed && <span className="sidebar-label">{item.label}</span>}
            </button>
          ))}
        </div>
      </nav>

      {/* Footer */}
      <div className="sidebar-footer">
        {!isCollapsed ? (
          <div className="sidebar-footer-content">
            <div className="sidebar-footer-links">
              <button className="sidebar-footer-link">Help</button>
              <button className="sidebar-footer-link">What's New</button>
              <button className="sidebar-footer-link">About</button>
            </div>
            <div className="sidebar-version">
              <span className="version-dot"></span>
              <span>v1.0.0</span>
            </div>
          </div>
        ) : (
          <div className="sidebar-footer-collapsed">
            <div className="sidebar-version-collapsed">
              <span className="version-dot"></span>
            </div>
          </div>
        )}
      </div>
    </aside>
  )
}