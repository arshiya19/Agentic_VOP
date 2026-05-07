import { useState } from 'react'
import Topbar from '../components/Topbar'
import Sidebar from '../components/Sidebar'
import '../App.css'

export default function UserManagement() {
  const [users] = useState([])
  const [editingUser, setEditingUser] = useState(null)

  const updateUserRole = (_userId, _newRole) => { // eslint-disable-line no-unused-vars
    setEditingUser(null)
  }

  return (
    <>
      <Topbar />
      <div className="app-layout">
        <Sidebar />
        <main className="dashboard-main">
          <div className="dashboard-header">
            <h1>User Management</h1>
            <p className="dashboard-subtitle">Manage system users and permissions</p>
          </div>

          {users.length === 0 ? (
            <div className="no-data">
              <p>No users found.</p>
            </div>
          ) : (
            <div className="vuln-table-container">
              <table className="vuln-table">
                <thead>
                  <tr>
                    <th>Email</th>
                    <th>Role</th>
                    <th>Created</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((user) => (
                    <tr key={user.id}>
                      <td>{user.email}</td>
                      <td>
                        {editingUser === user.id ? (
                          <select
                            value={user.role}
                            onChange={(e) => updateUserRole(user.id, e.target.value)}
                            style={{
                              padding: '0.25rem 0.5rem',
                              border: '1px solid var(--border-primary)',
                              borderRadius: 'var(--radius)',
                              background: 'var(--bg-primary)',
                              color: 'var(--text-primary)'
                            }}
                          >
                            <option value="user">User</option>
                            <option value="admin">Admin</option>
                          </select>
                        ) : (
                          <span className={`role-badge ${user.role}`}>
                            {user.role}
                          </span>
                        )}
                      </td>
                      <td>{new Date(user.created_at).toLocaleDateString()}</td>
                      <td>
                        {editingUser === user.id ? (
                          <button
                            className="action-btn"
                            onClick={() => setEditingUser(null)}
                          >
                            Cancel
                          </button>
                        ) : (
                          <button
                            className="action-btn"
                            onClick={() => setEditingUser(user.id)}
                          >
                            Edit
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </main>
      </div>
    </>
  )
}