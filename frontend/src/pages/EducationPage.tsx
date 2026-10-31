import { Icon } from '../components/Icons'

const warnings = [
  { icon: 'mail' as const, title: 'Unexpected urgency', text: 'Messages pressuring you to act immediately, or threatening account closure, deserve extra scrutiny.' },
  { icon: 'link' as const, title: 'Unfamiliar links', text: 'Check the real destination before opening. Look for misspellings, unusual domains, and shortened links.' },
  { icon: 'alert' as const, title: 'Requests for secrets', text: 'Legitimate organizations rarely ask for passwords, one-time codes, or payment details by message.' },
  { icon: 'external' as const, title: 'Sender mismatch', text: 'Display names can be spoofed. Inspect the complete sender address and verify through a known channel.' },
]
const tips = [
  'Navigate to websites using a saved bookmark or a trusted search—not a message link.',
  'Verify unexpected payment, password, or account requests through an official contact method.',
  'Use unique passwords and multi-factor authentication on important accounts.',
  'Report suspicious messages to your organization or service provider, then delete them.',
]

export function EducationPage() {
  return <div className="education-page"><div className="page-heading"><div><span className="section-kicker">SECURITY AWARENESS</span><h1>Learn & protect</h1><p>Recognize common social-engineering tactics and make safer choices online.</p></div></div>
    <section className="education-hero"><div className="education-hero-icon"><Icon name="shield" size={27}/></div><div><span className="section-kicker">KNOW THE THREAT</span><h2>What is phishing?</h2><p>Phishing is a form of social engineering where an attacker impersonates a trusted person or organization to trick someone into revealing information, transferring money, or opening a harmful link or file. It can arrive by email, SMS, social media, or phone.</p></div></section>
    <section className="education-section"><div className="section-title-row"><div><span className="section-kicker">SPOT THE SIGNALS</span><h2>Common warning signs</h2></div></div><div className="warning-grid">{warnings.map((warning, index) => <article className="warning-card" key={warning.title}><span className={`warning-icon warning-tone-${index}`}><Icon name={warning.icon} size={18}/></span><h3>{warning.title}</h3><p>{warning.text}</p></article>)}</div></section>
    <section className="tips-section"><div className="tips-heading"><span className="tips-icon"><Icon name="check" size={17}/></span><div><span className="section-kicker">PRACTICAL DEFENSE</span><h2>Safer habits, every day</h2></div></div><ul>{tips.map((tip) => <li key={tip}><span><Icon name="check" size={14}/></span>{tip}</li>)}</ul></section>
    <div className="education-disclaimer"><Icon name="info" size={16}/><p>Phishing tactics evolve. No automated scanner or list of warning signs catches every threat. When in doubt, verify independently using contact information you already trust.</p></div>
  </div>
}
