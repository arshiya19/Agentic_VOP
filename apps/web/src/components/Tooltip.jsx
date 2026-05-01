import { useState } from "react"
import { createPortal } from "react-dom"
import "../styles/Tooltip.css"

export default function Tooltip({ content, children }) {
  const [visible, setVisible] = useState(false)
  const [pos, setPos] = useState({ top: 0, left: 0 })

  const show = (e) => {
    const rect = e.currentTarget.getBoundingClientRect()
    setPos({
      top: rect.top - 9,
      left: rect.left + rect.width / 2 + 40,
    })
    setVisible(true)
  }

  const hide = () => setVisible(false)

  return (
    <>
      <span
        className="tooltip-trigger"
        onMouseEnter={show}
        onMouseLeave={hide}
      >
        {children}
      </span>

      {visible &&
        createPortal(
          <div
            className="tooltip-content"
            style={{
              top: `${pos.top}px`,
              left: `${pos.left}px`,
            }}
          >
            {content}
          </div>,
          document.body
        )}
    </>
  )
}
