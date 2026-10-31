import { useState } from 'react'
import { getApiHealth } from './api'

type ConnectionState = 'idle' | 'checking' | 'connected' | 'error'

function App() {
  const [connection, setConnection] = useState<ConnectionState>('idle')
  const [message, setMessage] = useState('')

  async function checkConnection() {
    setConnection('checking')
    setMessage('Checking the local FastAPI service…')

    try {
      const health = await getApiHealth()
      setConnection('connected')
      setMessage(`${health.service} is responding.`)
    } catch (error) {
      setConnection('error')
      setMessage(error instanceof Error ? error.message : 'Could not reach the API.')
    }
  }

  return (
    <main className="app-shell">
      <nav className="topbar" aria-label="Main navigation">
        <a className="brand" href="#home" aria-label="PhishGuard home">
          <span className="brand-mark" aria-hidden="true">P</span>
          <span>phish<span className="brand-light">guard</span></span>
        </a>
        <span className="environment"><span className="status-dot" /> LOCAL WORKSPACE</span>
      </nav>

      <section className="hero" id="home">
        <div className="hero-copy">
          <div className="eyebrow"><span className="eyebrow-line" /> SECURITY ANALYSIS WORKSPACE</div>
          <h1>Clarity in a<br /><span>threatening</span> inbox.</h1>
          <p className="intro">An explainable phishing detection platform, built to show its work. This workspace is the project foundation; detection and scan history will be added next.</p>
          <div className="hero-actions">
            <button className="primary-button" onClick={checkConnection} disabled={connection === 'checking'}>
              {connection === 'checking' ? 'Connecting…' : 'Test API connection'}
              <span aria-hidden="true">↗</span>
            </button>
            <a className="text-link" href="http://127.0.0.1:8000/docs" target="_blank" rel="noreferrer">Explore API docs <span aria-hidden="true">↗</span></a>
          </div>
          <div className={`connection-card connection-${connection}`} role="status" aria-live="polite">
            <span className="connection-indicator" />
            <div>
              <strong>{connection === 'connected' ? 'Backend connected' : connection === 'error' ? 'Backend unavailable' : connection === 'checking' ? 'Connecting to backend' : 'API connection not checked'}</strong>
              <p>{message || 'Start the FastAPI server, then test the connection.'}</p>
            </div>
          </div>
        </div>

        <aside className="preview-card" aria-label="Project foundation status">
          <div className="card-topline"><span>PROJECT FOUNDATION</span><span className="live-label"><i /> INITIALIZED</span></div>
          <div className="shield-art" aria-hidden="true">
            <div className="orbit orbit-one" /><div className="orbit orbit-two" />
            <div className="shield"><span>✓</span></div>
            <span className="spark spark-one">✳</span><span className="spark spark-two">✦</span>
          </div>
          <div className="preview-copy">
            <span className="muted-label">DETECTION ENGINE</span>
            <h2>Not configured yet</h2>
            <p>No predictions are generated in this setup phase. The next step is adding a trained, verifiable model and its analysis pipeline.</p>
          </div>
          <div className="stack-list">
            <div><span className="stack-icon react-icon">R</span><span>React + Vite</span><span className="stack-state">READY</span></div>
            <div><span className="stack-icon api-icon">⚡</span><span>FastAPI service</span><span className="stack-state">READY</span></div>
            <div><span className="stack-icon db-icon">◈</span><span>SQLite + ML pipeline</span><span className="stack-state pending">NEXT</span></div>
          </div>
        </aside>
      </section>

      <footer className="footer"><span>PHISHGUARD <span className="footer-divider">/</span> EXPLAINABLE SECURITY</span><span>DEVELOPMENT FOUNDATION · V0.1</span></footer>
    </main>
  )
}

export default App
