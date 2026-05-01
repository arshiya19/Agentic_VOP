import { useEffect, useMemo, useRef, useState } from 'react'
import './App.css'
import Topbar from './components/Topbar'
import Sidebar from './components/Sidebar'

// Chat UI shell. All state is local — no persistence, no backend call yet.
// Wire `sendMessage` to your agent endpoint when the API is ready.
export default function App() {
  const [sessions, setSessions] = useState([])
  const [activeId, setActiveId] = useState(null)
  const [input, setInput] = useState('')
  const [asking] = useState(false)

  const chat = useMemo(
    () => sessions.find((s) => s.id === activeId) ?? sessions[0],
    [sessions, activeId]
  )

  const messagesEndRef = useRef(null)

  useEffect(() => {
    if (messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({ behavior: 'smooth', block: 'end' })
    }
  }, [chat?.messages?.length, asking])

  function startNewChat() {
    const id = crypto.randomUUID()
    const newSession = {
      id,
      title: 'New chat',
      messages: [],
      createdAt: new Date(),
      updatedAt: new Date(),
    }
    setSessions((prev) => [newSession, ...prev])
    setActiveId(id)
    setInput('')
  }

  function renameActive(title) {
    setSessions((prev) => prev.map((s) => (s.id === activeId ? { ...s, title } : s)))
  }

  function deleteSession(id) {
    setSessions((prev) => prev.filter((s) => s.id !== id))
    if (id === activeId) {
      const remaining = sessions.filter((s) => s.id !== id)
      setActiveId(remaining[0]?.id ?? null)
    }
  }

  function addMsg(role, content, extras = {}) {
    setSessions((prev) =>
      prev.map((s) =>
        s.id === activeId
          ? { ...s, messages: [...s.messages, { role, content, ...extras }], updatedAt: new Date() }
          : s
      )
    )
  }

  // Wire to the agent backend when ready.
  async function sendMessage(question) {
    addMsg('user', question)
  }

  async function send() {
    const q = input.trim()
    if (!q || asking) return
    if (!chat) {
      startNewChat()
      return
    }
    if (chat.title === 'New chat') renameActive(q.slice(0, 40) || 'Chat')
    setInput('')
    await sendMessage(q)
  }

  const showHero = (chat?.messages?.length ?? 0) === 0

  const groupedSessions = useMemo(() => {
    const now = new Date()
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate())
    const yesterday = new Date(today)
    yesterday.setDate(yesterday.getDate() - 1)
    const weekAgo = new Date(today)
    weekAgo.setDate(weekAgo.getDate() - 7)

    const groups = { today: [], yesterday: [], week: [], older: [] }

    sessions.forEach((session) => {
      const sessionDate = new Date(session.updatedAt || session.createdAt)
      const sessionDay = new Date(
        sessionDate.getFullYear(),
        sessionDate.getMonth(),
        sessionDate.getDate()
      )
      if (sessionDay.getTime() === today.getTime()) groups.today.push(session)
      else if (sessionDay.getTime() === yesterday.getTime()) groups.yesterday.push(session)
      else if (sessionDate >= weekAgo) groups.week.push(session)
      else groups.older.push(session)
    })

    return groups
  }, [sessions])

  return (
    <>
      <Topbar />
      <div className="app-layout">
        <Sidebar
          sessions={sessions}
          groupedSessions={groupedSessions}
          activeId={activeId}
          onSessionClick={setActiveId}
          onNewChat={startNewChat}
          onDeleteSession={deleteSession}
        />

        <main className="chat-main">
          <div className="chat-content">
            {showHero ? (
              <div className="chat-input-hero">
                <h1 className="chat-input-hero-title">
                  Ask me <span className="chat-input-hero-highlight">anything</span>
                </h1>
              </div>
            ) : (
              <div className="chat-messages">
                {chat?.messages?.map((m, i) => (
                  <Message key={i} {...m} />
                ))}
                {asking && <Typing />}
                <div ref={messagesEndRef} style={{ height: '1px' }} />
              </div>
            )}
          </div>

          <div className="chat-input-section">
            <div className="chat-input-container">
              <div className="chat-input-wrapper">
                <textarea
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && !e.shiftKey) {
                      e.preventDefault()
                      send()
                    }
                  }}
                  placeholder="Type your question..."
                  rows={1}
                />
                <button onClick={send} disabled={!input.trim() || asking} className="chat-send-btn">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <line x1="22" y1="2" x2="11" y2="13"></line>
                    <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
                  </svg>
                </button>
              </div>
            </div>
          </div>
        </main>
      </div>
    </>
  )
}

function Message({ role, content, sources }) {
  const who = role === 'user' ? 'You' : role === 'assistant' ? 'Bot' : 'System'
  return (
    <div className={`msg ${role}`}>
      <div className="who">{who}</div>
      <div className="bubble">
        <div className="text">{content}</div>
        {sources?.length ? (
          <div className="sources">
            {[...new Set(sources.map((s) => s.source))].map((src, i) => (
              <span key={i} className="chip">
                {src}
              </span>
            ))}
          </div>
        ) : null}
      </div>
    </div>
  )
}

function Typing() {
  return (
    <div className="msg assistant">
      <div className="who">Bot</div>
      <div className="bubble typing">
        <span className="dot" />
        <span className="dot" />
        <span className="dot" />
      </div>
    </div>
  )
}
