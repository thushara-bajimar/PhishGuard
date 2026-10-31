import type { ScanRecord, ScanStatistics } from '../api'
import { Icon } from '../components/Icons'
import { MetricCard } from '../components/MetricCard'
import { ScanTable } from '../components/ScanTable'
import type { Page } from '../components/AppShell'

export function Dashboard({ scans, total, stats, loading, error, onRefresh, onNavigate, onView }: { scans: ScanRecord[]; total: number | null; stats: ScanStatistics | null; loading: boolean; error: string | null; onRefresh: () => void; onNavigate: (page: Page) => void; onView: (scan: ScanRecord) => void }) {
  return <div className="dashboard-page">
    <div className="page-heading"><div><span className="section-kicker">SECURITY OVERVIEW</span><h1>Good to see you.</h1><p>Monitor scan activity and inspect potential threats in your workspace.</p></div><button className="secondary-button" onClick={onRefresh} disabled={loading}><Icon name="refresh" size={15} /> Refresh data</button></div>
    <section className="metric-grid" aria-label="Scan statistics">
      <MetricCard label="Total scans" value={stats?.total_scans ?? total} note={total === null ? 'Awaiting scan history API' : 'All recorded analyses'} icon="grid" tone="blue" />
      <MetricCard label="Phishing detections" value={stats?.phishing_detections ?? null} note={stats ? 'Potential phishing predictions' : 'Awaiting statistics API'} icon="alert" tone="red" />
      <MetricCard label="Suspicious results" value={stats?.suspicious_results ?? null} note={stats ? 'High or critical risk category' : 'Awaiting statistics API'} icon="search" tone="amber" />
    </section>
    <section className="quick-section"><div className="section-title-row"><div><span className="section-kicker">START AN ANALYSIS</span><h2>Quick access</h2></div></div><div className="quick-grid">
      <button className="quick-card" onClick={() => onNavigate('url')}><span className="quick-icon quick-blue"><Icon name="link" /></span><span className="quick-copy"><strong>Scan a URL</strong><small>Check a suspicious web address</small></span><Icon name="arrow" size={17} /></button>
      <button className="quick-card" onClick={() => onNavigate('message')}><span className="quick-icon quick-violet"><Icon name="mail" /></span><span className="quick-copy"><strong>Scan a message</strong><small>Review email or SMS content</small></span><Icon name="arrow" size={17} /></button>
    </div></section>
    <section className="recent-section"><div className="section-title-row"><div><span className="section-kicker">ACTIVITY</span><h2>Recent scans</h2></div><button className="text-action" onClick={() => onNavigate('history')}>View all <Icon name="arrow" size={14} /></button></div>
      {loading ? <div className="state-card"><span className="loading-spinner" /><span>Loading scan activity…</span></div> : error ? <div className="state-card state-error"><span className="state-symbol"><Icon name="info" size={17} /></span><div><strong>History is not available</strong><p>{error}</p></div><button className="inline-button" onClick={onRefresh}>Retry</button></div> : scans.length === 0 ? <div className="state-card state-empty"><span className="state-symbol"><Icon name="clock" size={18} /></span><div><strong>No scans recorded yet</strong><p>Complete an analysis with a trained model and your recent result will appear here.</p></div></div> : <ScanTable scans={scans.slice(0, 5)} onView={onView} compact />}
    </section>
    <div className="dashboard-note"><Icon name="info" size={16} /><span>Risk scores and model predictions are informational only and never guarantee a URL or message is safe.</span></div>
  </div>
}
