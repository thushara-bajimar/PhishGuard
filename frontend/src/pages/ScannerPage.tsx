import { useState, type FormEvent } from 'react'
import { ApiError, analyzeMessage, analyzeUrl, type AnalysisResult, type ScanType } from '../api'
import { AnalysisResult as ResultPanel } from '../components/AnalysisResult'
import { Icon } from '../components/Icons'

export function ScannerPage({ type, onScanComplete, onApiStatus }: { type: ScanType; onScanComplete?: () => void; onApiStatus?: (online: boolean) => void }) {
  const [value, setValue] = useState('')
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [validationError, setValidationError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const isUrl = type === 'url'

  function validate(): string | null {
    const trimmed = value.trim()
    if (!trimmed) return isUrl ? 'Enter a URL to analyze.' : 'Paste the email or SMS content to analyze.'
    if (isUrl) {
      if (trimmed.length > 4096) return 'URLs must be 4,096 characters or fewer.'
      try {
        const candidate = new URL(/^[a-zA-Z][a-zA-Z\d+.-]*:\/\//.test(trimmed) ? trimmed : `https://${trimmed}`)
        if (!['http:', 'https:'].includes(candidate.protocol) || !candidate.hostname) return 'Enter a valid HTTP or HTTPS web address.'
      } catch {
        return 'Enter a valid web address, such as example.com.'
      }
    } else if (trimmed.length > 30_000) {
      return 'Message text must be 30,000 characters or fewer.'
    }
    return null
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const validationError = validate()
    if (validationError) { setValidationError(validationError); setError(null); setResult(null); return }
    setValidationError(null)
    setError(null)
    setResult(null)
    setLoading(true)
    try {
      const response = isUrl ? await analyzeUrl(value.trim()) : await analyzeMessage(value.trim())
      setResult(response)
      onApiStatus?.(true)
      onScanComplete?.()
    } catch (reason) {
      onApiStatus?.(reason instanceof ApiError && reason.status !== undefined)
      setError(reason instanceof Error ? reason.message : 'Analysis could not be completed. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  return <div className="scanner-page">
    <div className="page-heading"><div><span className="section-kicker">THREAT ANALYSIS</span><h1>{isUrl ? 'URL scanner' : 'Message scanner'}</h1><p>{isUrl ? 'Inspect a suspicious link for phishing signals and risk indicators.' : 'Review email or SMS content for suspicious language and links.'}</p></div></div>
    <div className="scanner-layout"><section className="scanner-card"><div className="scanner-card-heading"><span className={`large-scan-icon ${isUrl ? 'quick-blue' : 'quick-violet'}`}><Icon name={isUrl ? 'link' : 'mail'} size={20} /></span><div><h2>{isUrl ? 'Analyze a web address' : 'Analyze message content'}</h2><p>{isUrl ? 'The URL is sent to the configured analysis service.' : 'Message content is sent to the configured analysis service.'}</p></div></div>
      <form onSubmit={submit} noValidate>
        <label className="input-label" htmlFor="scan-input">{isUrl ? 'URL TO INSPECT' : 'EMAIL OR SMS CONTENT'}</label>
        {isUrl ? <div className={`url-input-wrap ${validationError ? 'input-error' : ''}`}><Icon name="link" size={17} /><input id="scan-input" type="text" inputMode="url" autoComplete="url" maxLength={4096} placeholder="https://example.com/suspicious-link" value={value} onChange={(event) => { setValue(event.target.value); setValidationError(null); setError(null) }} aria-invalid={Boolean(validationError)} aria-describedby={validationError ? 'scan-error' : 'scan-hint'} /></div> : <textarea id="scan-input" className={`message-input ${validationError ? 'input-error' : ''}`} placeholder="Paste the email or SMS text here…" value={value} onChange={(event) => { setValue(event.target.value); setValidationError(null); setError(null) }} rows={9} maxLength={30_000} aria-invalid={Boolean(validationError)} aria-describedby={validationError ? 'scan-error' : 'scan-hint'} />}
        <div className="input-meta"><span id={validationError ? 'scan-error' : 'scan-hint'} className={validationError ? 'validation-error' : ''} role={validationError ? 'alert' : undefined}>{validationError ? <><Icon name="alert" size={14} />{validationError}</> : isUrl ? 'Include the full address if possible. Both http and https URLs are supported.' : 'Avoid including personal information that is not needed for analysis.'}</span>{!isUrl && <span>{value.length.toLocaleString()} / 30,000 characters</span>}</div>
        <button type="submit" className="analyze-button" disabled={loading}>{loading ? <><span className="button-spinner" />Analyzing with configured service…</> : <><Icon name="search" size={16} />Analyze {isUrl ? 'URL' : 'message'}<Icon name="arrow" size={16} /></>}</button>
      </form>
      <div className="scanner-privacy"><Icon name="shield" size={15} /><span>Analysis requires an available backend. Avoid entering sensitive credentials or private data.</span></div>
    </section>
    <aside className="scanner-aside" aria-label="Analysis guidance"><div className="aside-card"><span className="aside-icon"><Icon name="spark" size={18} /></span><h3>How analysis works</h3><p>Your input is processed by the configured model and analysis pipeline. Results include model predictions and independently labeled heuristic indicators when the API supports them.</p><div className="aside-rule"/><span className="aside-foot"><Icon name="info" size={14} />No analysis is fabricated in this interface.</span></div><div className="aside-warning"><Icon name="alert" size={16} /><p><strong>Use caution: </strong>Never open a suspicious link based only on an automated scan result.</p></div></aside></div>
    {loading && <div className="analysis-loading" role="status"><span className="loading-spinner"/><div><strong>Waiting for analysis response</strong><p>No result is shown until the API returns its assessment.</p></div></div>}
    {error && !loading && <div className="error-banner" role="alert"><Icon name="alert" size={18}/><div><strong>Analysis unavailable</strong><p>{error}</p></div><button className="icon-button" onClick={() => setError(null)} aria-label="Dismiss error"><Icon name="close" size={17}/></button></div>}
    {result && <ResultPanel result={result} />}
  </div>
}
