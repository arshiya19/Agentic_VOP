import { useState, useRef, useEffect, useMemo } from 'react'
import '../styles/ColumnToggle.css'

/**
 * ColumnToggle - Dynamic column visibility toggle
 */
export default function ColumnToggle({
  data = [],
  columns: customColumns,
  visibleColumns = [],
  onChange,
  excludeColumns = ['id', 'uuid', 'created_at', 'updated_at'],
  defaultHidden = []
}) {
  const [isOpen, setIsOpen] = useState(false)
  const [selectedColumns, setSelectedColumns] = useState([])
  const dropdownRef = useRef(null)

  // Auto-detect columns from data if not provided
  const columns = useMemo(() => {
    if (customColumns && customColumns.length > 0) {
      return customColumns
    }

    if (!data || data.length === 0) return []

    const allKeys = new Set()
    data.forEach(item => {
      Object.keys(item).forEach(key => allKeys.add(key))
    })

    return Array.from(allKeys)
      .filter(key => !excludeColumns.includes(key))
      .map(key => ({
        key,
        label: formatColumnLabel(key)
      }))
  }, [data, customColumns, excludeColumns])

  // Initialize visible columns
  useEffect(() => {
    if (visibleColumns.length > 0) {
      setSelectedColumns([...visibleColumns])
    } else if (columns.length > 0) {
      const defaultVisible = columns
        .map(c => c.key)
        .filter(key => !defaultHidden.includes(key))
      setSelectedColumns(defaultVisible)
      if (onChange) onChange(defaultVisible)
    }
  }, [columns.length])

  // Sync with parent when visibleColumns changes externally
  useEffect(() => {
    if (visibleColumns.length > 0) {
      setSelectedColumns([...visibleColumns])
    }
  }, [visibleColumns])

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setIsOpen(false)
        setSelectedColumns([...visibleColumns])
      }
    }

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside)
    }

    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [isOpen, visibleColumns])

  const allColumnKeys = columns.map(col => col.key)
  const allSelected = selectedColumns.length === columns.length

  const handleToggleColumn = (key, e) => {
    e.preventDefault()
    e.stopPropagation()

    setSelectedColumns(prev => {
      if (prev.includes(key)) {
        // Don't allow deselecting if only 1 column is selected
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
      setSelectedColumns([columns[0]?.key].filter(Boolean))
    } else {
      setSelectedColumns([...allColumnKeys])
    }
  }

  const handleApply = (e) => {
    e.preventDefault()
    e.stopPropagation()

    const orderedColumns = allColumnKeys.filter(key => selectedColumns.includes(key))
    if (onChange) onChange(orderedColumns)
    setIsOpen(false)
  }

  const handleReset = (e) => {
    e.preventDefault()
    e.stopPropagation()

    const defaultVisible = allColumnKeys.filter(key => !defaultHidden.includes(key))
    setSelectedColumns(defaultVisible)
    if (onChange) onChange(defaultVisible)
    setIsOpen(false)
  }

  const handleToggleDropdown = (e) => {
    e.preventDefault()
    e.stopPropagation()
    setIsOpen(!isOpen)
  }

  if (columns.length === 0) return null

  const selectedCount = selectedColumns.length
  const totalCount = columns.length

  // Don't show badge during initialization (when selectedCount is 0)
  const showBadge = selectedCount > 0 && selectedCount < totalCount

  return (
    <div className="column-toggle" ref={dropdownRef}>
      <button
        type="button"
        className={`column-toggle-btn ${isOpen ? 'active' : ''}`}
        onClick={handleToggleDropdown}
        title="Toggle columns"
      >
       <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
  <line x1="4" y1="6" x2="20" y2="6"></line>
  <circle cx="8" cy="6" r="2" fill="currentColor"></circle>
  <line x1="4" y1="12" x2="20" y2="12"></line>
  <circle cx="16" cy="12" r="2" fill="currentColor"></circle>
  <line x1="4" y1="18" x2="20" y2="18"></line>
  <circle cx="10" cy="18" r="2" fill="currentColor"></circle>
</svg>
        {showBadge && (
          <span className="column-toggle-badge">{selectedCount}</span>
        )}
      </button>

      {isOpen && (
        <div className="column-toggle-dropdown" onClick={(e) => e.stopPropagation()}>
          <div className="column-toggle-header">
            <span className="column-toggle-title">Show Columns</span>
            <span className="column-toggle-count">{selectedCount} of {totalCount}</span>
          </div>

          <div className="column-toggle-options">
            {/* Select All */}
            <div
              className="column-toggle-option select-all"
              onClick={handleSelectAll}
            >
              <div className={`checkmark ${allSelected ? 'checked' : ''}`}>
                {allSelected && (
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
                    <polyline points="20 6 9 17 4 12"></polyline>
                  </svg>
                )}
              </div>
              <span className="option-label">Select All</span>
            </div>

            <div className="column-toggle-divider"></div>

            {/* Individual Columns */}
            {columns.map(col => {
              const isChecked = selectedColumns.includes(col.key)
              return (
                <div
                  key={col.key}
                  className="column-toggle-option"
                  onClick={(e) => handleToggleColumn(col.key, e)}
                >
                  <div className={`checkmark ${isChecked ? 'checked' : ''}`}>
                    {isChecked && (
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
                        <polyline points="20 6 9 17 4 12"></polyline>
                      </svg>
                    )}
                  </div>
                  <span className="option-label">{col.label}</span>
                </div>
              )
            })}
          </div>

          <div className="column-toggle-footer">
            <button type="button" className="column-toggle-reset" onClick={handleReset}>
              Reset
            </button>
            <button type="button" className="column-toggle-apply" onClick={handleApply}>
              Apply
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

/**
 * Convert column key to human-readable label
 */
function formatColumnLabel(key) {
  const abbreviations = {
    'id': 'ID',
    'cve': 'CVE',
    'cvss': 'CVSS',
    'cwe': 'CWE',
    'ip': 'IP',
    'url': 'URL',
    'api': 'API',
    'sql': 'SQL',
    'xss': 'XSS',
    'os': 'OS',
    'vm': 'VM',
    'aws': 'AWS',
    'gcp': 'GCP',
  }

  return key
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .replace(/_/g, ' ')
    .split(' ')
    .map(word => {
      const lower = word.toLowerCase()
      if (abbreviations[lower]) return abbreviations[lower]
      return word.charAt(0).toUpperCase() + word.slice(1).toLowerCase()
    })
    .join(' ')
}

/**
 * Hook for easy column visibility management
 */
export function useColumnVisibility(data, excludeColumns = ['id', 'uuid', 'created_at', 'updated_at'], defaultHidden = []) {
  const [visibleColumns, setVisibleColumns] = useState([])

  useEffect(() => {
    if (data && data.length > 0 && visibleColumns.length === 0) {
      const allKeys = new Set()
      data.forEach(item => {
        Object.keys(item).forEach(key => allKeys.add(key))
      })

      const detected = Array.from(allKeys)
        .filter(key => !excludeColumns.includes(key))
        .filter(key => !defaultHidden.includes(key))

      setVisibleColumns(detected)
    }
  }, [data])

  const isVisible = (columnKey) => visibleColumns.includes(columnKey)

  return { visibleColumns, setVisibleColumns, isVisible }
}
