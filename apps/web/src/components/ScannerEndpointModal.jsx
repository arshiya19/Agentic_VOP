import { useEffect, useRef, useState } from 'react'

const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

const ACCEPT_EXT = '.json,.jsonl,.ndjson,.csv,.sarif,application/json,text/csv'
const MAX_BYTES = 50 * 1024 * 1024

/* A unified modal that both creates new scanners and edits existing ones.
   Source types:
     - "api":  PATCH/POST with endpoint + headers + method
     - "file": multipart upload to /admin/scanners/{tool}/upload

   Props:
     tool      : catalog entry { id, name, authType }
     existing  : ScannerConfig from /admin/scanners, or null
     onClose   : () => void
     onSaved   : (successMessage: string) => void  // parent renders a toast
*/
export default function ScannerEndpointModal({ tool, existing, onClose, onSaved }) {
  // Source-type tab: 'api' or 'file'. Defaults based on existing connector.
  const [sourceType, setSourceType] = useState(
    existing?.connector_type === 'file_upload' ? 'file' : 'api'
  )

  // --- API fields ---
  const [endpoint, setEndpoint] = useState('')
  const [method, setMethod] = useState('GET')
  const [responsePath, setResponsePath] = useState('')
  const [headers, setHeaders] = useState([{ key: '', value: '' }])

  // --- File fields ---
  const fileInputRef = useRef(null)
  const [pendingFile, setPendingFile] = useState(null) // File object selected by user
  const [dragOver, setDragOver] = useState(false)

  // --- Shared ---
  const [enabled, setEnabled] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    if (!tool) return
    setError(null)
    setPendingFile(null)

    if (existing) {
      setSourceType(existing.connector_type === 'file_upload' ? 'file' : 'api')
      setEndpoint(existing.endpoint || '')
      const m = existing.metadata || {}
      setMethod((m.http_method || 'GET').toUpperCase())
      setResponsePath(m.response_path || '')
      const hdrs = m.headers || {}
      const hdrList = Object.entries(hdrs).map(([key, value]) => ({ key, value }))
      setHeaders(hdrList.length ? hdrList : [{ key: '', value: '' }])
      setEnabled(existing.enabled)
    } else {
      setSourceType('api')
      setEndpoint('')
      setMethod('GET')
      setResponsePath('')
      setHeaders([{ key: '', value: '' }])
      setEnabled(true)
    }
  }, [tool, existing])

  if (!tool) return null

  // ---------- API helpers ----------
  const updateHeader = (i, field, value) => {
    setHeaders((prev) => prev.map((h, idx) => (idx === i ? { ...h, [field]: value } : h)))
  }
  const addHeader = () => setHeaders((prev) => [...prev, { key: '', value: '' }])
  const removeHeader = (i) => {
    setHeaders((prev) =>
      prev.length <= 1 ? [{ key: '', value: '' }] : prev.filter((_, idx) => idx !== i)
    )
  }

  const buildApiMetadata = () => {
    const hdrs = {}
    for (const { key, value } of headers) {
      if (key.trim()) hdrs[key.trim()] = value
    }
    const meta = { http_method: method, headers: hdrs }
    if (responsePath.trim()) meta.response_path = responsePath.trim()
    return meta
  }

  // ---------- File helpers ----------
  const onPickFile = (f) => {
    if (!f) return
    if (f.size > MAX_BYTES) {
      setError(`File is larger than ${MAX_BYTES / (1024 * 1024)} MB.`)
      return
    }
    setError(null)
    setPendingFile(f)
  }

  const onDrop = (e) => {
    e.preventDefault()
    setDragOver(false)
    const f = e.dataTransfer?.files?.[0]
    if (f) onPickFile(f)
  }

  // ---------- Save ----------
  const handleSave = async () => {
    setSaving(true)
    setError(null)
    try {
      if (sourceType === 'api') {
        if (!endpoint.trim()) {
          throw new Error('Endpoint URL is required.')
        }
        const metadata = buildApiMetadata()
        let res
        if (existing && existing.connector_type !== 'file_upload') {
          res = await fetch(`${API_URL}/admin/scanners/${tool.id}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ endpoint: endpoint.trim(), enabled, metadata }),
          })
        } else {
          // Either brand-new or switching from file → api: register fresh.
          res = await fetch(`${API_URL}/admin/scanners`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              tool: tool.id,
              endpoint: endpoint.trim(),
              connector_type: 'user_endpoint',
              protocol: 'REST',
              auth_type: 'custom',
              metadata,
              enabled,
            }),
          })
          if (res.status === 409) {
            // Already exists (was a file_upload), PATCH instead.
            res = await fetch(`${API_URL}/admin/scanners/${tool.id}`, {
              method: 'PATCH',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                endpoint: endpoint.trim(),
                enabled,
                metadata: { ...metadata, connector_type: 'user_endpoint' },
              }),
            })
          }
        }
        if (!res.ok) {
          const body = await res.json().catch(() => ({}))
          throw new Error(body.detail || `HTTP ${res.status}`)
        }
        onSaved?.(
          existing
            ? `${tool.name} endpoint updated.`
            : `${tool.name} registered — added to Run a scan.`
        )
        onClose?.()
      } else {
        // file upload
        if (!pendingFile) {
          throw new Error('Pick a file first.')
        }
        const form = new FormData()
        form.append('file', pendingFile)
        const res = await fetch(`${API_URL}/admin/scanners/${tool.id}/upload`, {
          method: 'POST',
          body: form,
        })
        if (!res.ok) {
          const body = await res.json().catch(() => ({}))
          throw new Error(body.detail || `HTTP ${res.status}`)
        }
        onSaved?.(`${tool.name}: uploaded ${pendingFile.name}.`)
        onClose?.()
      }
    } catch (e) {
      setError(`Save failed: ${e.message}`)
    } finally {
      setSaving(false)
    }
  }

  // ---------- Render ----------
  const isFile = sourceType === 'file'
  const currentFilename = existing?.metadata?.file_filename
  const currentFormat = existing?.metadata?.file_format

  return (
    <div className="integration-modal-overlay" onClick={onClose}>
      <div className="integration-modal" onClick={(e) => e.stopPropagation()} style={{ width: 560 }}>
        <h2>{tool.name}</h2>
        <p>
          {existing
            ? `Update the connector configuration for this tool.`
            : `Connect ${tool.name} — paste an API endpoint or upload a scanner export.`}
        </p>

        {/* Source-type toggle */}
        <div className="sem-source-tabs">
          <button
            type="button"
            className={`sem-source-tab ${!isFile ? 'active' : ''}`}
            onClick={() => setSourceType('api')}
          >
            API endpoint
          </button>
          <button
            type="button"
            className={`sem-source-tab ${isFile ? 'active' : ''}`}
            onClick={() => setSourceType('file')}
          >
            File upload
          </button>
        </div>

        {error && (
          <div className="amc-banner amc-banner-err" style={{ marginBottom: 12 }}>
            {error}
          </div>
        )}

        <div className="integration-form">
          {!isFile ? (
            <>
              <label className="sem-label">Endpoint URL</label>
              <span className="sem-help">
                The full URL we’ll call to fetch findings. Check the tool’s API docs — usually a
                “list findings” or “export vulnerabilities” endpoint.
              </span>
              <input
                type="text"
                placeholder="https://api.example.com/v1/findings"
                value={endpoint}
                onChange={(e) => setEndpoint(e.target.value)}
              />

              <label className="sem-label">HTTP method</label>
              <span className="sem-help">
                Usually <strong>GET</strong>. Pick <strong>POST</strong> only if the tool’s docs
                say so.
              </span>
              <div className="sem-method-row">
                {['GET', 'POST'].map((m) => (
                  <button
                    key={m}
                    type="button"
                    className={`sem-method-btn ${method === m ? 'active' : ''}`}
                    onClick={() => setMethod(m)}
                  >
                    {m}
                  </button>
                ))}
              </div>

              <label className="sem-label">Headers (e.g. Authorization)</label>
              <span className="sem-help">
                Auth header the tool needs. Most APIs use{' '}
                <code>Authorization: Bearer &lt;token&gt;</code> or{' '}
                <code>X-API-Key: &lt;key&gt;</code>. Leave empty for public APIs.
              </span>
              <div className="sem-headers">
                {headers.map((h, i) => (
                  <div key={i} className="sem-header-row">
                    <input
                      type="text"
                      placeholder="Authorization"
                      value={h.key}
                      onChange={(e) => updateHeader(i, 'key', e.target.value)}
                    />
                    <input
                      type="text"
                      placeholder="Bearer eyJhbGciOi…"
                      value={h.value}
                      onChange={(e) => updateHeader(i, 'value', e.target.value)}
                    />
                    <button
                      type="button"
                      className="sem-header-remove"
                      onClick={() => removeHeader(i)}
                      aria-label="Remove header"
                    >
                      ×
                    </button>
                  </div>
                ))}
                <button type="button" className="sem-add-header" onClick={addHeader}>
                  + Add header
                </button>
              </div>

              <label className="sem-label">Response path (optional)</label>
              <span className="sem-help">
                Where the findings array lives inside the response. Auto-detects common keys
                (<code>findings</code>, <code>vulnerabilities</code>, …); the LLM infers nested
                paths automatically on first scan.
              </span>
              <input
                type="text"
                placeholder="e.g. data.findings"
                value={responsePath}
                onChange={(e) => setResponsePath(e.target.value)}
              />
            </>
          ) : (
            <>
              <label className="sem-label">Scanner export file</label>
              <span className="sem-help">
                Drop a <strong>JSON</strong>, <strong>JSONL</strong>, <strong>CSV</strong>, or{' '}
                <strong>SARIF</strong> file. Up to 50&nbsp;MB. Format is auto-detected from the
                extension and content.
              </span>

              <div
                className={`sem-dropzone ${dragOver ? 'over' : ''}`}
                onDragOver={(e) => {
                  e.preventDefault()
                  setDragOver(true)
                }}
                onDragLeave={() => setDragOver(false)}
                onDrop={onDrop}
                onClick={() => fileInputRef.current?.click()}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept={ACCEPT_EXT}
                  style={{ display: 'none' }}
                  onChange={(e) => onPickFile(e.target.files?.[0])}
                />
                {pendingFile ? (
                  <>
                    <div className="sem-dropzone-filename">{pendingFile.name}</div>
                    <div className="sem-dropzone-meta">
                      {(pendingFile.size / 1024).toFixed(1)} KB · click or drop to replace
                    </div>
                  </>
                ) : currentFilename ? (
                  <>
                    <div className="sem-dropzone-filename">Currently: {currentFilename}</div>
                    <div className="sem-dropzone-meta">
                      format: {currentFormat || 'unknown'} · click or drop to replace
                    </div>
                  </>
                ) : (
                  <>
                    <div className="sem-dropzone-icon">⬆</div>
                    <div className="sem-dropzone-hint">Click to select, or drop file here</div>
                    <div className="sem-dropzone-meta">.json · .jsonl · .csv · .sarif</div>
                  </>
                )}
              </div>
            </>
          )}

          <label className="sem-checkbox-row">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
            />
            <span>Enabled (show in “Run a scan”)</span>
          </label>
        </div>

        <div className="integration-modal-actions">
          <button className="integration-close-btn" onClick={onClose} disabled={saving}>
            Cancel
          </button>
          <button
            className="scanner-runner-btn"
            onClick={handleSave}
            disabled={saving}
            style={{ minWidth: 120 }}
          >
            {saving
              ? isFile
                ? 'Uploading…'
                : 'Saving…'
              : existing
                ? 'Update'
                : isFile
                  ? 'Upload'
                  : 'Register'}
          </button>
        </div>
      </div>
    </div>
  )
}
