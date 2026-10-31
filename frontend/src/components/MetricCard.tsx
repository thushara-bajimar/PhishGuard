import { Icon } from './Icons'

export function MetricCard({ label, value, note, icon, tone }: { label: string; value: number | string | null; note: string; icon: 'grid' | 'alert' | 'search'; tone: 'blue' | 'red' | 'amber' }) {
  return <article className="metric-card"><div className={`metric-icon metric-${tone}`}><Icon name={icon} size={18} /></div><div className="metric-label">{label}</div><div className="metric-value">{value ?? '—'}</div><div className="metric-note">{note}</div></article>
}
