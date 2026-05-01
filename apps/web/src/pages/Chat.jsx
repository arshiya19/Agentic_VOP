import React, { useState, useRef, useEffect } from 'react'
import Topbar from '../components/Topbar'
import Sidebar from '../components/Sidebar'
import '../styles/Chat.css'

export default function Chat() {
  const [messages, setMessages] = useState([])
  const [input, setInput] = useState('')
  const [isLoading] = useState(false)
  const messagesEndRef = useRef(null)

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  useEffect(() => {
    scrollToBottom()
  }, [messages])

  // Wire to your agent backend when available.
  const handleSend = async () => {
    const q = input.trim()
    if (!q || isLoading) return

    const userMessage = { id: Date.now(), role: 'user', content: q }
    setMessages((prev) => [...prev, userMessage])
    setInput('')
  }

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  return (
    <div className="chat-page-wrapper">
      <Topbar />
      <div className="chat-layout">
        <Sidebar />
        <main className="chat-main">
          <div className="chat-container">
            <div className="chat-header">
              <div className="chat-header-icon">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path>
                </svg>
              </div>
              <div className="chat-header-info">
                <h2>AI Assistant</h2>
                <span className="chat-status">
                  <span className="status-dot"></span>
                  Online
                </span>
              </div>
            </div>

            <div className="chat-messages">
              {messages.map((message) => (
                <div key={message.id} className={`message ${message.role === 'user' ? 'user' : 'bot'}`}>
                  {message.role === 'assistant' && (
                    <div className="message-avatar bot-avatar">
                      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <rect x="3" y="11" width="18" height="10" rx="2"></rect>
                        <circle cx="12" cy="5" r="2"></circle>
                        <path d="M12 7v4"></path>
                        <line x1="8" y1="16" x2="8" y2="16"></line>
                        <line x1="16" y1="16" x2="16" y2="16"></line>
                      </svg>
                    </div>
                  )}
                  <div className="message-content">
                    <span className="message-label">{message.role === 'assistant' ? 'AI Assistant' : 'You'}</span>
                    <div className="message-bubble">
                      {message.content}
                    </div>
                    {message.sources?.length > 0 && (
                      <div className="message-sources">
                        {[...new Set(message.sources.map(s => s.source))].map((src, i) => (
                          <span key={i} className="source-chip">{src}</span>
                        ))}
                      </div>
                    )}
                  </div>
                  {message.role === 'user' && (
                    <div className="message-avatar user-avatar">
                      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                        <circle cx="12" cy="7" r="4"></circle>
                      </svg>
                    </div>
                  )}
                </div>
              ))}

              {isLoading && (
                <div className="message bot">
                  <div className="message-avatar bot-avatar">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <rect x="3" y="11" width="18" height="10" rx="2"></rect>
                      <circle cx="12" cy="5" r="2"></circle>
                      <path d="M12 7v4"></path>
                    </svg>
                  </div>
                  <div className="message-content">
                    <span className="message-label">AI Assistant</span>
                    <div className="message-bubble typing">
                      <span className="typing-dot"></span>
                      <span className="typing-dot"></span>
                      <span className="typing-dot"></span>
                    </div>
                  </div>
                </div>
              )}

              <div ref={messagesEndRef} />
            </div>

            <div className="chat-input-container">
              <div className="chat-input-wrapper">
                <textarea
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={handleKeyPress}
                  placeholder="Type your question..."
                  rows={1}
                  disabled={isLoading}
                />
                <button
                  className="send-button"
                  onClick={handleSend}
                  disabled={!input.trim() || isLoading}
                >
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <line x1="22" y1="2" x2="11" y2="13"></line>
                    <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
                  </svg>
                </button>
              </div>
              <p className="chat-disclaimer">
                AI responses are for guidance only. Always verify critical security decisions.
              </p>
            </div>
          </div>
        </main>
      </div>
    </div>
  )
}
