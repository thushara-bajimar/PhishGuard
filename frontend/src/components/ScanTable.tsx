import type { ScanRecord } from '../api'
import { Icon } from './Icons'

export function ScanTable({ scans, onView, onDelete, deletingId, compact = false }: { scans: ScanRecord[]; onView: (scan: ScanRecord) => void; onDelete?: (scan: ScanRecord) => void; deletingId?: string | null; compact?: boolean }) {
  return <div className={`table-wrap ${compact ? 'table-compact' : ''}`}><table className="scan-table"><thead><tr><th>SCAN</th><th>TYPE</th><th>DATE</th><th>RESULT</th><th>RISK SCORE</th><th aria-label="Actions" /></tr></thead><tbody>
    {scans.map((scan) => <tr key={scan.id}>
      <td><button className="scan-name" onClick={() => onView(scan)}><span className={`scan-type-icon type-${scan.scan_type}`}>{scan.scan_type === 'url' ? <Icon name="link" size={15} /> : <Icon name="mail" size={15} />}</span><span>{scan.input_excerpt || (scan.scan_type === 'url' ? 'URL analysis' : 'Message analysis')}</span></button></td>
      <td><span className="type-label">{scan.scan_type === 'url' ? 'URL' : 'Message'}</span></td>
      <td className="date-cell">{Number.isNaN(Date.parse(scan.created_at)) ? scan.created_at : new Date(scan.created_at).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })}</td>
      <td><span className={`result-tag ${scan.prediction === 'potential_phishing' ? 'tag-phishing' : 'tag-clear'}`}><i />{scan.prediction === 'potential_phishing' ? 'Potential phishing' : 'No phishing detected'}</span></td>
      <td><span className={`score-cell score-text-${scan.risk_category}`}>{scan.risk_score}<span>/100</span></span><span className={`category-dot category-${scan.risk_category}`} /></td>
      <td><div className="row-actions"><button className="icon-button" title="View scan details" aria-label="View scan details" onClick={() => onView(scan)}><Icon name="chevron" size={16} /></button>{onDelete && <button className="icon-button delete-action" title="Delete scan" aria-label="Delete scan" disabled={deletingId === scan.id} onClick={() => onDelete(scan)}><Icon name="trash" size={15} /></button>}</div></td>
    </tr>)}
  </tbody></table></div>
}
