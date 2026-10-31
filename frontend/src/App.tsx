import { useCallback, useEffect, useState } from 'react'
import { ApiError, deleteScan, getApiHealth, getScanHistory, getScanStatistics, type ScanRecord, type ScanStatistics } from './api'
import { AppShell, type Page } from './components/AppShell'
import { ScanDetailsDialog } from './components/ScanDetailsDialog'
import { Dashboard } from './pages/Dashboard'
import { EducationPage } from './pages/EducationPage'
import { HistoryPage } from './pages/HistoryPage'
import { ScannerPage } from './pages/ScannerPage'

function App() {
  const [page, setPage] = useState<Page>('overview')
  const [apiOnline, setApiOnline] = useState<boolean | null>(null)
  const [scans, setScans] = useState<ScanRecord[]>([])
  const [total, setTotal] = useState<number | null>(null)
  const [stats, setStats] = useState<ScanStatistics | null>(null)
  const [historyOffset, setHistoryOffset] = useState(0)
  const [historyLoading, setHistoryLoading] = useState(true)
  const [historyError, setHistoryError] = useState<string | null>(null)
  const [selectedScan, setSelectedScan] = useState<ScanRecord | null>(null)
  const [deletingId, setDeletingId] = useState<string | null>(null)
  const closeScanDetails = useCallback(() => setSelectedScan(null), [])

  const refreshHistory = useCallback(async (offset = 0) => {
    setHistoryLoading(true)
    setHistoryError(null)
    try {
      const [history, statistics] = await Promise.all([getScanHistory(25, offset), getScanStatistics()])
      setScans(history.items)
      setHistoryOffset(history.offset)
      setTotal(history.total)
      setStats(statistics)
      setApiOnline(true)
    } catch (reason) {
      setHistoryError(reason instanceof ApiError ? reason.message : 'Could not load scan history.')
      setTotal(null)
      setStats(null)
      setApiOnline(reason instanceof ApiError && reason.status !== undefined)
    } finally {
      setHistoryLoading(false)
    }
  }, [])

  useEffect(() => {
    let active = true
    getApiHealth().then(() => { if (active) setApiOnline(true) }).catch(() => { if (active) setApiOnline(false) })
    void refreshHistory()
    return () => { active = false }
  }, [refreshHistory])

  async function removeScan(scan: ScanRecord) {
    if (!window.confirm('Delete this scan record? This cannot be undone.')) return
    setDeletingId(scan.id)
    try {
      await deleteScan(scan.id)
      if (selectedScan?.id === scan.id) setSelectedScan(null)
      const nextOffset = total !== null && historyOffset >= total - 1 ? Math.max(0, historyOffset - 25) : historyOffset
      await refreshHistory(nextOffset)
    } catch (reason) {
      window.alert(reason instanceof Error ? reason.message : 'The scan could not be deleted.')
    } finally {
      setDeletingId(null)
    }
  }

  let content
  if (page === 'overview') {
    content = <Dashboard scans={scans} total={total} stats={stats} loading={historyLoading} error={historyError} onRefresh={() => { void refreshHistory(0) }} onNavigate={setPage} onView={setSelectedScan} />
  } else if (page === 'url' || page === 'message') {
    content = <ScannerPage key={page} type={page} onApiStatus={setApiOnline} onScanComplete={() => { void refreshHistory(0) }} />
  } else if (page === 'history') {
    content = <HistoryPage scans={scans} total={total ?? 0} offset={historyOffset} pageSize={25} loading={historyLoading} error={historyError} onRefresh={() => { void refreshHistory(historyOffset) }} onPageChange={(offset) => { void refreshHistory(offset) }} onView={setSelectedScan} onDelete={(scan) => { void removeScan(scan) }} deletingId={deletingId} />
  } else {
    content = <EducationPage />
  }

  return (
    <AppShell page={page} onNavigate={setPage} apiOnline={apiOnline}>
      {content}
      <ScanDetailsDialog scan={selectedScan} onClose={closeScanDetails} />
    </AppShell>
  )
}

export default App
