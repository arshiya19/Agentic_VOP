import { useEffect, useRef, useState } from 'react'
import '../styles/ViewToggleEye.css'

export default function ViewToggleEyeDropdown({ viewMode, onChange }) {
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

  // Close on outside click
  useEffect(() => {
    const handleClickOutside = (e) => {
      if (ref.current && !ref.current.contains(e.target)) {
        setOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const handleSelect = (mode) => {
    onChange(mode)
    setOpen(false)
  }

  return (
    <div className="view-eye-dropdown" ref={ref}>
      {/* Eye Button */}
      <button
        className="view-toggle-eye"
        onClick={() => setOpen(o => !o)}
        title="Change table view"
        type="button"
      >
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8S1 12 1 12z" />
          <circle cx="12" cy="12" r="3" />
        </svg>
      </button>

      {/* Dropdown */}
      {open && (
        <div className="view-eye-menu">
          <button
            className={`view-eye-option ${viewMode === 'issue' ? 'active' : ''}`}
            onClick={() => handleSelect('issue')}
          >
            Issue View
          </button>

          <button
            className={`view-eye-option ${viewMode === 'asset' ? 'active' : ''}`}
            onClick={() => handleSelect('asset')}
          >
            Asset View
          </button>
        </div>
      )}
    </div>
  )
}
