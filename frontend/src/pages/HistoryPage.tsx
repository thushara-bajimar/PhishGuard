import type { ScanRecord } from '../api'
import { Icon } from '../components/Icons'
import { ScanTable } from '../components/ScanTable'

export function HistoryPage({ scans, loading, error, onRefresh, onView, onDelete, deletingId }: { scans: ScanRecord[]; loading: boolean; error: string | null; onRefresh: () => void; onView: (scan: ScanRecord) => void; onDelete: (scan: ScanRecord) => void; deletingId: string | number | null }) {
  return <div className="history-page"><div className="page-heading"><div><span className="section-kicker">YOUR ACTIVITY</span><h1>Scan history</h1><p>Review previous analyses and their returned risk assessments.</p></div><button className="secondary-button" onClick={onRefresh} disabled={loading}><Icon name="refresh" size={15}/> Refresh</button></div>
    <section className="history-card"><div className="history-toolbar"><div><h2>All scans</h2><span>{loading ? 'Updating…' : `${scans.length} ${scans.length === 1 ? 'record' : 'records'} loaded`}</span></div><div className="history-status"><span className={`api-dot ${error ? 'offline' : 'online'}`} />{error ? 'API unavailable' : 'Connected to scan history'}</div></div>
      {loading ? <div className="history-state"><span className="loading-spinner"/><strong>Loading scan history…</strong></div> : error ? <div className="history-state history-error"><span className="state-symbol"><Icon name="info" size={19}/></span><strong>Scan history could not be loaded</strong><p>{error}</p><button className="secondary-button" onClick={onRefresh}><Icon name="refresh" size={14}/> Try again</button></div> : scans.length === 0 ? <div className="history-state"><span className="empty-illustration"><Icon name="clock" size={23}/></span><strong>No scan records yet</strong><p>Completed analyses will be listed here once the backend history endpoint is available.</p></div> : <ScanTable scans={scans} onView={onView} onDelete={onDelete} deletingId={deletingId}/>}
    </section><div className="history-disclaimer"><Icon name="info" size={15}/>History displays API-returned records only; this view does not create sample or placeholder scans.</div>
  </div>
}
