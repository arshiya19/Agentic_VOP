import { useState, useRef, useEffect, useMemo } from 'react'
import '../styles/SeverityFilter.css'

const SEVERITY_OPTIONS = [
  { key: 'CRITICAL', label: 'Critical' },
  { key: 'HIGH', label: 'High' },
  { key: 'MEDIUM', label: 'Medium' },
  { key: 'LOW', label: 'Low' }
]

export default function SeverityFilter({
  data = [],
  value = [],
  onChange,
  field = 'severity'
}) {
  const [isOpen, setIsOpen] = useState(false)
  const [selectedSeverities, setSelectedSeverities] = useState([])
  const dropdownRef = useRef(null)

  const allKeys = SEVERITY_OPTIONS.map(o => o.key)

  // Initialize: sync with parent value
  // Empty array from parent means "all selected" (no filter)
  useEffect(() => {
    if (value.length === 0) {
      setSelectedSeverities([...allKeys])
    } else {
      setSelectedSeverities([...value])
    }
  }, [])

  // Sync with parent when value changes externally
  useEffect(() => {
    if (value.length === 0) {
      setSelectedSeverities([...allKeys])
    } else {
      setSelectedSeverities([...value])
    }
  }, [value])

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setIsOpen(false)
        if (value.length === 0) {
          setSelectedSeverities([...allKeys])
        } else {
          setSelectedSeverities([...value])
        }
      }
    }

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside)
    }

    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [isOpen, value])

  const counts = useMemo(() => {
    return SEVERITY_OPTIONS.reduce((acc, opt) => {
      acc[opt.key] = data.filter(i => i[field] === opt.key).length
      return acc
    }, {})
  }, [data, field])

  const allSelected = selectedSeverities.length === allKeys.length

  const handleToggleSeverity = (key, e) => {
    e.preventDefault()
    e.stopPropagation()

    setSelectedSeverities(prev => {
      if (prev.includes(key)) {
        // Don't allow deselecting if only 1 is selected
        if (prev.length === 1) return prev
        return prev.filter(k => k !== key)
      } else {
        return [...prev, key]
      }
    })
  }

  const handleSelectAll = (e) => {
    e.preventDefault()
    e.stopPropagation()

    if (allSelected) {
      setSelectedSeverities([allKeys[0]])
    } else {
      setSelectedSeverities([...allKeys])
    }
  }

  const handleApply = (e) => {
    e.preventDefault()
    e.stopPropagation()

    // If all are selected, pass empty array (meaning "all" / no filter)
    if (selectedSeverities.length === allKeys.length) {
      onChange?.([])
    } else {
      const orderedSeverities = allKeys.filter(key => selectedSeverities.includes(key))
      onChange?.(orderedSeverities)
    }
    setIsOpen(false)
  }

  const handleReset = (e) => {
    e.preventDefault()
    e.stopPropagation()

    setSelectedSeverities([...allKeys])
    onChange?.([])
    setIsOpen(false)
  }

  const handleToggleDropdown = (e) => {
    e.preventDefault()
    e.stopPropagation()
    setIsOpen(!isOpen)
  }

  const selectedCount = selectedSeverities.length
  const totalCount = allKeys.length

  // value.length === 0 means all selected, so no badge
  const showBadge = value.length > 0 && value.length < totalCount

  return (
    <div className="severity-filter" ref={dropdownRef}>
      <button
        type="button"
        className={`severity-filter-btn ${isOpen ? 'active' : ''}`}
        onClick={handleToggleDropdown}
        title="Filter by severity"
      >
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3" />
        </svg>
        {showBadge && (
          <span className="severity-filter-badge">{value.length}</span>
        )}
      </button>

      {isOpen && (
        <div className="severity-filter-dropdown" onClick={(e) => e.stopPropagation()}>
          <div className="severity-filter-header">
            <span className="severity-filter-title">SEVERITY</span>
            <span className="severity-filter-count">{selectedCount} of {totalCount}</span>
          </div>

          <div className="severity-filter-options">
            {/* Select All */}
            <div
              className="severity-filter-option select-all"
              onClick={handleSelectAll}
            >
              <div className={`checkmark ${allSelected ? 'checked' : ''}`}>
                {allSelected && <CheckIcon />}
              </div>
              <span className="option-label">Select All</span>
              <span className="severity-filter-count">{data.length}</span>
            </div>

            <div className="severity-filter-divider"></div>

            {/* Individual Options */}
            {SEVERITY_OPTIONS.map(opt => {
              const isSelected = selectedSeverities.includes(opt.key)

              return (
                <div
                  key={opt.key}
                  className="severity-filter-option"
                  onClick={(e) => handleToggleSeverity(opt.key, e)}
                >
                  <div className={`checkmark ${isSelected ? 'checked' : ''}`}>
                    {isSelected && <CheckIcon />}
                  </div>
                  <span className="option-label">{opt.label}</span>
                  <span className="severity-filter-count">
                    {counts[opt.key] ?? 0}
                  </span>
                </div>
              )
            })}
          </div>

          <div className="severity-filter-footer">
            <button
              type="button"
              className="severity-filter-reset"
              onClick={handleReset}
            >
              Reset
            </button>
            <button
              type="button"
              className="severity-filter-apply"
              onClick={handleApply}
            >
              Apply
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

// Helper for chip display text — used by Issues page.
// eslint-disable-next-line react-refresh/only-export-components
export function getSeverityChipText(value, data, field = 'severity') {
  const allKeys = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

  if (value.length === 0 || value.length === allKeys.length) {
    return `All(${data.length})`
  }

  const filteredCount = data.filter(item => value.includes(item[field])).length
  return `${value.join(', ')}(${filteredCount})`
}

function CheckIcon() {
  return (
    <svg
      width="12"
      height="12"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="3"
    >
      <polyline points="20 6 9 17 4 12" />
    </svg>
  )
}
