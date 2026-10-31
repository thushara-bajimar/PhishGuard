import { useEffect, useRef, useState } from 'react'
import { getScanDetails, type AnalysisResult, type ScanRecord } from '../api'
import { AnalysisResult as ResultPanel } from './AnalysisResult'
import { Icon } from './Icons'

export function ScanDetailsDialog({ scan, onClose }: { scan: ScanRecord | null; onClose: () => void }) {
  const dialogRef = useRef<HTMLElement>(null)
  const [detail, setDetail] = useState<AnalysisResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const scanId = scan?.id ?? null

  useEffect(() => {
    if (!scanId) { setDetail(null); setError(null); return }
    let active = true
    setLoading(true); setDetail(null); setError(null)
    getScanDetails(scanId).then((response) => { if (active) setDetail(response) }).catch((reason: unknown) => { if (active) setError(reason instanceof Error ? reason.message : 'Could not load scan details.') }).finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [scanId])

  useEffect(() => {
    if (!scanId) return
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null
    const dialog = dialogRef.current
    const getFocusable = () => [...(dialog?.querySelectorAll<HTMLElement>('button:not(:disabled), a[href], input:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex="-1"])') ?? [])]
    getFocusable()[0]?.focus()
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        onClose()
      } else if (event.key === 'Tab') {
        const focusable = getFocusable()
        if (!focusable.length) return
        const first = focusable[0]
        const last = focusable[focusable.length - 1]
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault()
          last.focus()
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault()
          first.focus()
        }
      }
    }
    window.addEventListener('keydown', onKey)
    return () => {
      window.removeEventListener('keydown', onKey)
      previousFocus?.focus()
    }
  }, [scanId, onClose])

  if (!scan) return null
  return <div className="dialog-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose() }}><section ref={dialogRef} className="details-dialog" role="dialog" aria-modal="true" aria-labelledby="details-title" tabIndex={-1}><div className="dialog-header"><div><span className="section-kicker">SCAN RECORD</span><h2 id="details-title">Analysis details</h2></div><button className="icon-button" onClick={onClose} aria-label="Close details"><Icon name="close"/></button></div>
    {loading ? <div className="history-state"><span className="loading-spinner"/><strong>Loading scan details…</strong></div> : error ? <div className="history-state history-error"><span className="state-symbol"><Icon name="info" size={19}/></span><strong>Details are unavailable</strong><p>{error}</p></div> : detail ? <div className="dialog-result"><ResultPanel result={detail}/></div> : null}
  </section></div>
}
