import type { CSSProperties } from 'react'
import type { AnalysisResult as AnalysisResultData, RiskCategory } from '../api'
import { Icon } from './Icons'

const categoryLabel: Record<RiskCategory, string> = { low: 'Low', medium: 'Medium', high: 'High', critical: 'Critical' }

export function AnalysisResult({ result }: { result: AnalysisResultData }) {
  const phishing = result.prediction === 'potential_phishing'
  return <section className="result-panel" aria-labelledby="result-title">
    <div className="result-heading"><div><span className="section-kicker">ANALYSIS COMPLETE</span><h2 id="result-title">Scan results</h2></div><span className={`risk-pill risk-${result.risk_category}`}>{categoryLabel[result.risk_category]} risk</span></div>
    <div className="result-summary">
      <div className={`score-ring score-${result.risk_category}`} role="img" aria-label={`Risk score ${result.risk_score} out of 100`} style={{ '--score': `${Math.max(0, Math.min(100, result.risk_score)) * 3.6}deg` } as CSSProperties}><div aria-hidden="true"><strong>{result.risk_score}</strong><span> / 100</span></div></div>
      <div className="prediction-copy"><span className="result-label">MODEL PREDICTION</span><h3 className={phishing ? 'prediction-danger' : 'prediction-safe'}>{phishing ? 'Potential phishing' : 'No phishing detected'}</h3><p>{result.model_name ? `Assessed by ${result.model_name}.` : 'Classification returned by the configured analysis service.'} This is an automated assessment, not a guarantee of safety.</p></div>
    </div>
    <><div className="confidence-line"><span>Predicted-class score</span><strong>{Math.round(result.model_confidence * 100)}%</strong></div>{result.model_info.risk_score_note && <p className="model-score-note">{result.model_info.risk_score_note}</p>}{result.model_info.scope_note && <p className="model-score-note">{result.model_info.scope_note}</p>}</>
    <div className="indicators"><div className="indicator-heading"><div><span className="section-kicker">WHY THIS RESULT</span><h3>Explainable indicators</h3></div><span className="indicator-count">{result.indicators.length} signals</span></div><p className="indicator-explanation">{result.explanation_note || 'Indicators are observable URL heuristics and are separate from the model prediction.'}</p>
      {result.indicators.length === 0 ? <div className="empty-inline">The analysis service returned no indicators for this scan.</div> : <div className="indicator-list">{result.indicators.map((indicator, index) => <article className="indicator-item" key={`${indicator.source}-${indicator.name}-${index}`}><span className={`indicator-source source-${indicator.source}`}>{indicator.source === 'model' ? 'MODEL' : 'HEURISTIC'}</span><div><strong>{indicator.name}</strong><p>{indicator.description}</p></div></article>)}</div>}
    </div>
    <div className="safety-disclaimer"><Icon name="info" size={17} /><p><strong>Safety note</strong>{result.disclaimer || 'A low score or “no phishing detected” result does not guarantee that a URL or message is safe. Verify the sender and destination independently.'}</p></div>
  </section>
}
