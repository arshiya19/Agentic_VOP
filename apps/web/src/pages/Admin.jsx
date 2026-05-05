import { useState } from 'react'
import Topbar from '../components/Topbar'
import Sidebar from '../components/Sidebar'
import '../App.css'

// Document Manager UI shell. Wire each handler to your backend when ready.
export default function Admin() {
  const [files] = useState([])
  const [stats] = useState(null)
  const [message] = useState('')
  const [namespace, setNamespace] = useState('')
  const [selectedFiles, setSelectedFiles] = useState([])
  const [description, setDescription] = useState('')

  const handleFileChange = (e) => {
    setSelectedFiles(Array.from(e.target.files))
  }

  const uploadDocs = async () => {
    setDescription('')
    setSelectedFiles([])
    const fileInput = document.querySelector('input[type="file"]')
    if (fileInput) fileInput.value = ''
  }

  const deleteFile = async (_name) => {} // eslint-disable-line no-unused-vars

  const switchNamespace = async () => {}

  const saveLLMConfig = async (_cfg) => {} // eslint-disable-line no-unused-vars

  return (
    <>
      <Topbar />
      <div className="app-layout">
        <Sidebar />
        <main className="admin-main two-col">
          {/* LEFT COLUMN */}
          <div className="col">
            <div className="card">
              <h3>Upload documents</h3>
              <input type="file" multiple onChange={handleFileChange} />
              <input
                type="text"
                placeholder="Enter description (e.g. July 2025 scan)"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
              <button onClick={uploadDocs} disabled={selectedFiles.length === 0}>
                Save
              </button>
            </div>

            <div className="card">
              <h3>Data manager</h3>
              {!files.length ? (
                <div className="muted">No files</div>
              ) : (
                <div className="scroll-card">
                  <table className="table">
                    <thead>
                      <tr>
                        <th>Name</th>
                        <th>Size</th>
                        <th>Modified</th>
                        <th>Description</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {files.map((f) => (
                        <tr key={f.name}>
                          <td>{f.name}</td>
                          <td>{(f.size / 1024).toFixed(1)} KB</td>
                          <td>{new Date(f.mtime * 1000).toLocaleString()}</td>
                          <td>{f.description || '—'}</td>
                          <td>
                            <button onClick={() => deleteFile(f.name)}>Delete</button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>

          {/* RIGHT COLUMN */}
          <div className="col">
            <div className="card sticky-card">
              <h3>LLM config</h3>
              <LLMConfigEditor onSave={saveLLMConfig} />
            </div>

            <div className="card">
              <h3>Namespace</h3>
              <div className="row">
                <input
                  value={namespace}
                  onChange={(e) => setNamespace(e.target.value)}
                  placeholder="default"
                />
                <button onClick={switchNamespace}>Switch</button>
              </div>
              <div className="small muted">Current namespace: {stats?.namespace ?? '—'}</div>
            </div>

            <div className="card">
              <h3>Index stats</h3>
              <div className="scroll-card">
                <pre className="pre">
                  {JSON.stringify(
                    {
                      index: stats?.index,
                      namespace: stats?.namespace,
                      namespace_stats: stats?.namespace_stats,
                    },
                    null,
                    2
                  )}
                </pre>
              </div>
            </div>

            {message && (
              <div className="card">
                <h3>Server response</h3>
                <div className="scroll-card">
                  <pre className="pre">{message}</pre>
                </div>
              </div>
            )}
          </div>
        </main>
      </div>
    </>
  )
}

// Local form for editing LLM config. State lives in this component until wired up.
function LLMConfigEditor({ onSave }) {
  const [cfg, setCfg] = useState({
    model: '',
    temperature: 0,
    top_k_default: 4,
    search_type: 'mmr',
    fetch_k: 20,
    lambda_mult: 0.5,
    system_prompt: '',
  })
  const [saving, setSaving] = useState(false)

  const modelOptions = [
    'claude-opus-4-7',
    'claude-sonnet-4-6',
    'claude-haiku-4-5',
    'gpt-4o-mini',
    'gpt-4',
  ]

  function field(k, type = 'text', step) {
    const val = cfg[k]
    if (k === 'search_type') {
      return (
        <label className="field" key={k}>
          <span>{k}</span>
          <select value={val} onChange={(e) => setCfg({ ...cfg, [k]: e.target.value })}>
            <option value="mmr">MMR</option>
            <option value="similarity">Similarity</option>
          </select>
        </label>
      )
    }
    if (k === 'model') {
      return (
        <label className="field" key={k}>
          <span>{k}</span>
          <select value={val} onChange={(e) => setCfg({ ...cfg, [k]: e.target.value })}>
            <option value="">— select —</option>
            {modelOptions.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
        </label>
      )
    }
    return (
      <label className="field" key={k}>
        <span>{k}</span>
        <input
          type={type}
          value={val}
          step={step}
          onChange={(e) =>
            setCfg({ ...cfg, [k]: type === 'number' ? Number(e.target.value) : e.target.value })
          }
        />
      </label>
    )
  }

  return (
    <>
      <div className="grid">
        {field('model')}
        {field('temperature', 'number', 0.1)}
        {field('top_k_default', 'number')}
        {field('search_type', 'select')}
        {field('fetch_k', 'number')}
        {field('lambda_mult', 'number', 0.1)}
      </div>
      <label className="field">
        <span>system_prompt</span>
        <textarea
          rows={4}
          value={cfg.system_prompt}
          onChange={(e) => setCfg({ ...cfg, system_prompt: e.target.value })}
        />
      </label>
      <button
        disabled={saving}
        onClick={async () => {
          setSaving(true)
          await onSave(cfg)
          setSaving(false)
        }}
      >
        {saving ? 'Saving…' : 'Save'}
      </button>
    </>
  )
}
