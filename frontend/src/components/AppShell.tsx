import type { ReactNode } from 'react'
import { useState } from 'react'
import { Icon } from './Icons'

export type Page = 'overview' | 'url' | 'message' | 'history' | 'learn'

const navigation: { id: Page; label: string; icon: 'grid' | 'link' | 'mail' | 'clock' | 'book' }[] = [
  { id: 'overview', label: 'Overview', icon: 'grid' },
  { id: 'url', label: 'URL scanner', icon: 'link' },
  { id: 'message', label: 'Message scanner', icon: 'mail' },
  { id: 'history', label: 'Scan history', icon: 'clock' },
  { id: 'learn', label: 'Learn & protect', icon: 'book' },
]

export function AppShell({ page, onNavigate, children, apiOnline }: { page: Page; onNavigate: (page: Page) => void; children: ReactNode; apiOnline: boolean | null }) {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const navigate = (next: Page) => { onNavigate(next); setSidebarOpen(false) }

  return <div className="workspace">
    {sidebarOpen && <button className="sidebar-backdrop" aria-label="Close navigation" onClick={() => setSidebarOpen(false)} />}
    <aside className={`sidebar ${sidebarOpen ? 'sidebar-open' : ''}`}>
      <button className="brand sidebar-brand" onClick={() => navigate('overview')} aria-label="PhishGuard overview">
        <span className="brand-mark"><Icon name="shield" size={19} /></span><span className="brand-name">phish<span>guard</span></span>
      </button>
      <div className="workspace-label">WORKSPACE</div>
      <nav className="side-nav" aria-label="Main navigation">
        {navigation.map((item) => <button key={item.id} className={`nav-item ${page === item.id ? 'nav-active' : ''}`} onClick={() => navigate(item.id)}>
          <Icon name={item.icon} size={17} /><span>{item.label}</span>{page === item.id && <i className="nav-active-mark" />}
        </button>)}
      </nav>
      <div className="sidebar-spacer" />
      <div className="sidebar-security-card"><div className="sidebar-card-icon"><Icon name="shield" size={16} /></div><strong>Stay one step ahead</strong><p>Learn to spot the signals before you click.</p><button onClick={() => navigate('learn')}>Explore safety tips <Icon name="arrow" size={13} /></button></div>
      <div className="sidebar-bottom"><span className={`api-dot ${apiOnline ? 'online' : apiOnline === false ? 'offline' : ''}`} /><span>Detection API</span><span className={`api-status ${apiOnline ? 'online-text' : apiOnline === false ? 'offline-text' : ''}`}>{apiOnline ? 'ONLINE' : apiOnline === false ? 'OFFLINE' : 'CHECKING'}</span></div>
      <div className="sidebar-version">PHISHGUARD <span>·</span> v0.1.0</div>
    </aside>
    <div className="main-column">
      <header className="topbar">
        <button className="mobile-menu" onClick={() => setSidebarOpen(true)} aria-label="Open navigation"><Icon name="menu" /></button>
        <div className="breadcrumb"><span>Workspace</span><Icon name="chevron" size={14} /><strong>{navigation.find((item) => item.id === page)?.label}</strong></div>
        <div className="topbar-right"><span className="secure-label"><span className="secure-dot" /> SECURE WORKSPACE</span><div className="avatar">PG</div></div>
      </header>
      <main className="page-content">{children}</main>
      <footer className="main-footer"><span>PhishGuard <i>·</i> Explainable security analysis</span><span>Predictions are informational, not guarantees of safety.</span></footer>
    </div>
  </div>
}
