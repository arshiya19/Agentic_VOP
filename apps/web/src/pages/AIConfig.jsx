import { useState } from "react";
import Topbar from "../components/Topbar";
import Sidebar from "../components/Sidebar";
import "../App.css";

export default function AIConfig() {
  const [config, setConfig] = useState({
    model: "",
    temperature: 0.7,
    top_k: 4,
    system_prompt: "",
    namespace: "default",
  });
  const [success] = useState("");
  const [error] = useState("");

  // Wire to /api/llm/config when the backend exists.
  async function saveConfig() {}

  return (
    <>
      <Topbar />
      <div className="app-layout">
        <Sidebar />
        <main className="dashboard-main">
          <div className="dashboard-header">
            <h1>AI Configuration</h1>
            <p className="dashboard-subtitle">Configure your AI model settings</p>
          </div>

          <div className="settings-container">
            <div className="settings-section">
              <h2>Model Settings</h2>
              <div className="form-group">
                <label>Model</label>
                <select
                  value={config.model}
                  onChange={(e) => setConfig({ ...config, model: e.target.value })}
                >
                  <option value="gpt-4">GPT-4</option>
                  <option value="gpt-3.5-turbo">GPT-3.5 Turbo</option>
                  <option value="gpt-4-turbo">GPT-4 Turbo</option>
                </select>
              </div>

              <div className="form-group">
                <label>Temperature ({config.temperature})</label>
                <input
                  type="range"
                  min="0"
                  max="2"
                  step="0.1"
                  value={config.temperature}
                  onChange={(e) =>
                    setConfig({ ...config, temperature: parseFloat(e.target.value) })
                  }
                />
                <small>Controls randomness: 0 is focused, 2 is creative</small>
              </div>

              <div className="form-group">
                <label>Top K Results</label>
                <input
                  type="number"
                  min="1"
                  max="20"
                  value={config.top_k}
                  onChange={(e) =>
                    setConfig({ ...config, top_k: parseInt(e.target.value) })
                  }
                />
                <small>Number of relevant documents to retrieve</small>
              </div>
            </div>

            <div className="settings-section">
              <h2>System Prompt</h2>
              <div className="form-group">
                <label>Custom Instructions</label>
                <textarea
                  rows="6"
                  value={config.system_prompt}
                  onChange={(e) => setConfig({ ...config, system_prompt: e.target.value })}
                  placeholder="Enter custom system instructions..."
                />
                <small>Define how the AI should behave and respond</small>
              </div>
            </div>

            <div className="settings-section">
              <h2>Namespace</h2>
              <div className="form-group">
                <label>Current Namespace</label>
                <input type="text" value={config.namespace} disabled />
                <small>Documents are organized by namespace</small>
              </div>
            </div>

            {error && <div className="auth-error">{error}</div>}
            {success && <div className="auth-success">{success}</div>}

            <div className="settings-section">
              <button className="primary wide" onClick={saveConfig}>
                Save Configuration
              </button>
            </div>
          </div>
        </main>
      </div>
    </>
  );
}
