import { useEffect, useState } from 'react'
import '../styles/AgentModelConfig.css'

const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

const AGENT_LABELS = {
  master: 'Master Orchestrator',
  'sub-agent-1': 'Sub-Agent 1 — Smart Connector',
  'sub-agent-2': 'Sub-Agent 2 — Enrichment Specialist',
}

const PROVIDER_LABELS = {
  openai: 'OpenAI',
  anthropic: 'Anthropic',
  google: 'Google Gemini',
}

function inferProvider(modelId) {
  if (!modelId) return 'openai'
  const id = modelId.toLowerCase()
  if (id.startsWith('claude-')) return 'anthropic'
  if (id.startsWith('gemini-')) return 'google'
  return 'openai'
}

export default function AgentModelConfig({ open, onClose }) {
  const [config, setConfig] = useState(null) // { agents, available_models, providers_configured }
  const [selections, setSelections] = useState({}) // agent -> model_id
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(null)
  const [saveMsg, setSaveMsg] = useState(null)

  useEffect(() => {
    if (!open) return
    setError(null)
    setSaveMsg(null)
    fetch(`${API_URL}/admin/agents/config`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        return r.json()
      })
      .then((data) => {
        setConfig(data)
        const initial = {}
        for (const a of data.agents) initial[a.agent] = a.current_model
        setSelections(initial)
      })
      .catch((e) => setError(`Failed to load: ${e.message}`))
  }, [open])

  if (!open) return null

  const handleChange = (agent, modelId) => {
    setSelections((prev) => ({ ...prev, [agent]: modelId }))
    setSaveMsg(null)
  }

  const handleSave = async () => {
    if (!config) return
    setSaving(true)
    setError(null)
    setSaveMsg(null)
    try {
      const changes = config.agents.filter(
        (a) => selections[a.agent] && selections[a.agent] !== a.current_model
      )
      for (const a of changes) {
        const res = await fetch(`${API_URL}/admin/agents/${a.agent}/model`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ model: selections[a.agent] }),
        })
        if (!res.ok) {
          const body = await res.json().catch(() => ({}))
          throw new Error(body.detail || `HTTP ${res.status}`)
        }
      }
      setSaveMsg(
        changes.length === 0
          ? 'No changes.'
          : `Saved ${changes.length} model selection${changes.length > 1 ? 's' : ''}.`
      )
      // Refresh so current_model reflects the saved state.
      const refreshed = await fetch(`${API_URL}/admin/agents/config`).then((r) => r.json())
      setConfig(refreshed)
    } catch (e) {
      setError(`Save failed: ${e.message}`)
    } finally {
      setSaving(false)
    }
  }

  const renderAgentRow = (agentCfg) => {
    const selected = selections[agentCfg.agent]
    const isRecommended = selected === agentCfg.recommended_model
    const selectedProvider = inferProvider(selected)
    const providerAvailable = config.providers_configured[selectedProvider]

    return (
      <div className="amc-agent-row" key={agentCfg.agent}>
        <div className="amc-agent-meta">
          <div className="amc-agent-name">{AGENT_LABELS[agentCfg.agent] || agentCfg.agent}</div>
          <div className="amc-agent-recommended">
            Recommended: <span className="amc-mono">{agentCfg.recommended_model}</span>
          </div>
        </div>

        <div className="amc-select-wrap">
          <select
            className="amc-select"
            value={selected || ''}
            onChange={(e) => handleChange(agentCfg.agent, e.target.value)}
          >
            {Object.entries(config.available_models).map(([provider, models]) => (
              <optgroup
                key={provider}
                label={`${PROVIDER_LABELS[provider] || provider}${
                  config.providers_configured[provider] ? '' : ' (API key missing)'
                }`}
              >
                {models.map((m) => (
                  <option
                    key={m.id}
                    value={m.id}
                    disabled={!config.providers_configured[provider]}
                  >
                    {m.label}
                    {m.id === agentCfg.recommended_model ? '  ✓ Recommended' : ''}
                  </option>
                ))}
              </optgroup>
            ))}
          </select>

          <div className="amc-row-warnings">
            {isRecommended ? (
              <span className="amc-pill amc-pill-ok">✓ Recommended — tested end-to-end</span>
            ) : (
              <span className="amc-pill amc-pill-warn">
                ⚠ Custom model — normalization quality and risk scoring may vary
              </span>
            )}
            {!providerAvailable && (
              <span className="amc-pill amc-pill-err">
                ⚠ {PROVIDER_LABELS[selectedProvider]} API key not set in .env — scans using
                this model will fail until the key is added.
              </span>
            )}
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="amc-backdrop" onClick={onClose}>
      <div className="amc-modal" onClick={(e) => e.stopPropagation()}>
        <div className="amc-header">
          <div>
            <h2>Model Configuration</h2>
            <p className="amc-sub">
              Pick which LLM each agent uses. The recommended models are tested end-to-end
              across all current scanners; switching is supported but results may vary.
            </p>
          </div>
          <button className="amc-close" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>

        {error && <div className="amc-banner amc-banner-err">{error}</div>}
        {saveMsg && <div className="amc-banner amc-banner-ok">{saveMsg}</div>}

        <div className="amc-body">
          {!config ? (
            <div className="amc-loading">Loading…</div>
          ) : (
            config.agents.map(renderAgentRow)
          )}
        </div>

        <div className="amc-footer">
          <button className="amc-btn amc-btn-ghost" onClick={onClose} disabled={saving}>
            Cancel
          </button>
          <button className="amc-btn amc-btn-primary" onClick={handleSave} disabled={saving || !config}>
            {saving ? 'Saving…' : 'Save'}
          </button>
        </div>
      </div>
    </div>
  )
}
