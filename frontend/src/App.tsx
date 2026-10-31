import { useCallback, useEffect, useState } from 'react'
import { ApiError, deleteScan, getApiHealth, getScanHistory, type ScanRecord } from './api'
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
  const [historyLoading, setHistoryLoading] = useState(true)
  const [historyError, setHistoryError] = useState<string | null>(null)
  const [selectedScan, setSelectedScan] = useState<ScanRecord | null>(null)
  const [deletingId, setDeletingId] = useState<string | number | null>(null)

  const refreshHistory = useCallback(async () => {
    setHistoryLoading(true)
    setHistoryError(null)
    try {
      const history = await getScanHistory()
      setScans(history.items)
      setTotal(history.total ?? history.items.length)
    } catch (reason) {
      setHistoryError(reason instanceof ApiError ? reason.message : 'Could not load scan history.')
      setTotal(null)
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
      setScans((current) => current.filter((item) => item.id !== scan.id))
      setTotal((current) => current === null ? null : Math.max(0, current - 1))
      if (selectedScan?.id === scan.id) setSelectedScan(null)
    } catch (reason) {
      window.alert(reason instanceof Error ? reason.message : 'The scan could not be deleted.')
    } finally {
      setDeletingId(null)
    }
  }

  let content
  if (page === 'overview') {
    content = <Dashboard scans={scans} total={total} loading={historyLoading} error={historyError} onRefresh={() => { void refreshHistory() }} onNavigate={setPage} onView={setSelectedScan} />
  } else if (page === 'url' || page === 'message') {
    content = <ScannerPage key={page} type={page} onScanComplete={() => { void refreshHistory() }} />
  } else if (page === 'history') {
    content = <HistoryPage scans={scans} loading={historyLoading} error={historyError} onRefresh={() => { void refreshHistory() }} onView={setSelectedScan} onDelete={(scan) => { void removeScan(scan) }} deletingId={deletingId} />
  } else {
    content = <EducationPage />
  }

  return (
    <AppShell page={page} onNavigate={setPage} apiOnline={apiOnline}>
      {content}
      <ScanDetailsDialog scan={selectedScan} onClose={() => setSelectedScan(null)} />
    </AppShell>
  )
}

export default App
