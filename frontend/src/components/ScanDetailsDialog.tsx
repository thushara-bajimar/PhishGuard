import { useEffect, useState } from 'react'
import { getScanDetails, type AnalysisResult, type ScanRecord } from '../api'
import { AnalysisResult as ResultPanel } from './AnalysisResult'
import { Icon } from './Icons'

export function ScanDetailsDialog({ scan, onClose }: { scan: ScanRecord | null; onClose: () => void }) {
  const [detail, setDetail] = useState<AnalysisResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => {
    if (!scan) { setDetail(null); setError(null); return }
    let active = true
    setLoading(true); setDetail(null); setError(null)
    getScanDetails(scan.id).then((response) => { if (active) setDetail(response) }).catch((reason: unknown) => { if (active) setError(reason instanceof Error ? reason.message : 'Could not load scan details.') }).finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [scan])

  useEffect(() => {
    if (!scan) return
    const onKey = (event: KeyboardEvent) => { if (event.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [scan, onClose])

  if (!scan) return null
  return <div className="dialog-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose() }}><section className="details-dialog" role="dialog" aria-modal="true" aria-labelledby="details-title"><div className="dialog-header"><div><span className="section-kicker">SCAN RECORD</span><h2 id="details-title">Analysis details</h2></div><button className="icon-button" onClick={onClose} aria-label="Close details"><Icon name="close"/></button></div>
    {loading ? <div className="history-state"><span className="loading-spinner"/><strong>Loading scan details…</strong></div> : error ? <div className="history-state history-error"><span className="state-symbol"><Icon name="info" size={19}/></span><strong>Details are unavailable</strong><p>{error}</p></div> : detail ? <div className="dialog-result"><ResultPanel result={detail}/></div> : null}
  </section></div>
}
