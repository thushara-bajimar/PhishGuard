import type { ReactNode, SVGProps } from 'react'

type IconName = 'grid' | 'link' | 'mail' | 'clock' | 'book' | 'settings' | 'search' | 'arrow' | 'shield' | 'menu' | 'close' | 'external' | 'trash' | 'chevron' | 'alert' | 'check' | 'info' | 'refresh' | 'spark'

const paths: Record<IconName, ReactNode> = {
  grid: <><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/></>,
  link: <><path d="M10 13.5 8.5 15a4 4 0 0 1-5.7-5.7l4-4a4 4 0 0 1 5.7 0"/><path d="m14 10.5 1.5-1.5a4 4 0 0 1 5.7 5.7l-4 4a4 4 0 0 1-5.7 0"/><path d="m8.5 15.5 7-7"/></>,
  mail: <><rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/></>,
  clock: <><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></>,
  book: <><path d="M4 5.5A2.5 2.5 0 0 1 6.5 3H20v17H6.5A2.5 2.5 0 0 1 4 17.5z"/><path d="M4 17.5A2.5 2.5 0 0 1 6.5 15H20M8 7h8M8 10h6"/></>,
  settings: <><circle cx="12" cy="12" r="3"/><path d="m19.4 15 .1.1 1.2.9-1.2 2.1-1.4-.5a7.7 7.7 0 0 1-1.7 1l-.2 1.5h-2.4l-.3-1.5a7.7 7.7 0 0 1-1.7-1l-1.4.5-1.2-2.1 1.2-.9a7.6 7.6 0 0 1 0-2l-1.2-.9 1.2-2.1 1.4.5a7.7 7.7 0 0 1 1.7-1l.3-1.5h2.4l.2 1.5a7.7 7.7 0 0 1 1.7 1l1.4-.5 1.2 2.1-1.2.9a7.6 7.6 0 0 1 0 2Z" transform="translate(-1 -1)"/></>,
  search: <><circle cx="10.8" cy="10.8" r="6.8"/><path d="m16 16 4.5 4.5"/></>,
  arrow: <><path d="M5 12h14M13 6l6 6-6 6"/></>,
  shield: <><path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z"/><path d="m9 12 2 2 4-4"/></>,
  menu: <><path d="M4 7h16M4 12h16M4 17h16"/></>,
  close: <><path d="m18 6-12 12M6 6l12 12"/></>,
  external: <><path d="M14 4h6v6M20 4l-9 9"/><path d="M18 13v6a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h6"/></>,
  trash: <><path d="M3 6h18M8 6V4h8v2m3 0-1 14H6L5 6m4 4v6m6-6v6"/></>,
  chevron: <path d="m9 18 6-6-6-6"/>,
  alert: <><path d="m10.3 3.9-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.7-3.1l-8-14a2 2 0 0 0-3.4 0Z"/><path d="M12 9v4m0 4h.01"/></>,
  check: <path d="m5 12 4 4L19 6"/>,
  info: <><circle cx="12" cy="12" r="10"/><path d="M12 16v-4m0-4h.01"/></>,
  refresh: <><path d="M20 7v5h-5M4 17v-5h5"/><path d="M5.5 9A7 7 0 0 1 17 6l3 6M4 12l3 6a7 7 0 0 0 11.5-3"/></>,
  spark: <><path d="m12 3 1.9 5.8L20 11l-6.1 2.2L12 19l-1.9-5.8L4 11l6.1-2.2L12 3Z"/><path d="m19 14 1 2.5 2 1-2 1-1 2.5-1-2.5-2-1 2-1 1-2.5Z"/></>,
}

export function Icon({ name, size = 18, ...props }: SVGProps<SVGSVGElement> & { name: IconName; size?: number }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" {...props}>{paths[name]}</svg>
}
