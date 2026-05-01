import { useState, useEffect, useRef, useMemo } from 'react'

export default function MultiSelectFilter({
  title,
  options = [],
  value = [],
  onChange,
  onOpenChange
}) {
  const dropdownRef = useRef(null)
  const [isOpen, setIsOpen] = useState(false)

  const allKeys = useMemo(() => options.map(o => o.key), [options])
  const [selected, setSelected] = useState([])

  const allSelected = selected.length === allKeys.length

  useEffect(() => {
    onOpenChange?.(isOpen)
  }, [isOpen, onOpenChange])

  // Sync with parent value AND options
  useEffect(() => {
    if (value.length === 0) {
      setSelected(allKeys)
    } else {
      setSelected(value)
    }
  }, [value, allKeys])

  // Close on outside click
  useEffect(() => {
    const handleClickOutside = (e) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
        setIsOpen(false)
        setSelected(value.length === 0 ? allKeys : value)
      }
    }

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside)
    }

    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [isOpen, value, allKeys])

  const toggle = (key) => {
    setSelected(prev => {
      if (prev.includes(key)) {
        if (prev.length === 1) return prev
        return prev.filter(k => k !== key)
      }
      return [...prev, key]
    })
  }

  const toggleSelectAll = () => {
    setSelected(allSelected ? [] : allKeys)
  }

  const apply = () => {
    onChange(selected.length === allKeys.length ? [] : selected)
    setIsOpen(false)
  }

  const reset = () => {
    setSelected(allKeys)
    onChange([])
    setIsOpen(false)
  }

  const showBadge =
    value.length > 0 && value.length < allKeys.length

  return (
    <div className="severity-filter" ref={dropdownRef}>
      <button
        type="button"
        className={`severity-filter-btn ${isOpen ? 'active' : ''}`}
        onClick={() => setIsOpen(v => !v)}
        title={title}
      >
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3" />
        </svg>

        {showBadge && (
          <span className="severity-filter-badge">
            {value.length}
          </span>
        )}
      </button>

      {isOpen && (
        <div className="severity-filter-dropdown">
          <div className="severity-filter-header">
            <span className="severity-filter-title">
              {title.toUpperCase()}
            </span>
            <span className="severity-filter-count">
              {selected.length} of {allKeys.length}
            </span>
          </div>

          <div className="severity-filter-options">
            {/* SELECT ALL */}
            <div
              className="severity-filter-option select-all"
              onClick={toggleSelectAll}
            >
              <div className={`checkmark ${allSelected ? 'checked' : ''}`}>
                {allSelected && <CheckIcon />}
              </div>
              <span className="option-label">Select All</span>
            </div>

            <div className="severity-filter-divider" />

            {/* OPTIONS */}
            {options.map(opt => {
              const isSelected = selected.includes(opt.key)

              return (
                <div
                  key={opt.key}
                  className="severity-filter-option"
                  onClick={() => toggle(opt.key)}
                >
                  <div className={`checkmark ${isSelected ? 'checked' : ''}`}>
                    {isSelected && <CheckIcon />}
                  </div>
                  <span className="option-label">{opt.label}</span>
                  <span className="severity-filter-count">{opt.count}</span>
                </div>
              )
            })}
          </div>

          <div className="severity-filter-footer">
            <button
              type="button"
              className="severity-filter-reset"
              onClick={reset}
            >
              Reset
            </button>

            <button
              type="button"
              className="severity-filter-apply"
              onClick={apply}
            >
              Apply
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

function CheckIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
      <polyline points="20 6 9 17 4 12" />
    </svg>
  )
}
