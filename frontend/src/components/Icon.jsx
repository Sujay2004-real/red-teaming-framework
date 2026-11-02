const paths = {
  shield: <><path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z" /><path d="m8 12 3 3 5-6" /></>,
  reader: <><path d="M14 3H6v18h12V7l-4-4Z" /><path d="M14 3v5h4M9 12h6M9 16h6" /></>,
  registrar: <><rect x="3" y="5" width="18" height="14" rx="2" /><path d="M3 10h18M8 15h3M12 5V3" /></>,
  planner: <><circle cx="12" cy="12" r="9" /><path d="m16 8-3 5-5 3 3-5 5-3Z" /></>,
  executor: <path d="m13 3-9 11h7l-1 7 10-12h-7l1-6Z" />,
  exploiter: <><circle cx="12" cy="12" r="8" /><circle cx="12" cy="12" r="3" /><path d="m12 12 9-9M17 3h4v4" /></>,
  analyst: <><circle cx="10" cy="10" r="6" /><path d="m15 15 6 6M7 10h6M10 7v6" /></>,
  reporter: <><path d="M14 3H5v18h14V8l-5-5ZM14 3v5h5M8 12h8M8 16h5" /></>,
  arrow: <path d="M4 12h16m-6-6 6 6-6 6" />,
  chevron: <path d="m6 9 6 6 6-6" />,
  check: <path d="m5 12 4 4L19 6" />,
  lock: <><rect x="5" y="10" width="14" height="11" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3" /></>,
  upload: <><path d="M12 16V3m-5 5 5-5 5 5M4 16v4h16v-4" /></>,
  close: <path d="m6 6 12 12M18 6 6 18" />,
  target: <><rect x="3" y="4" width="18" height="13" rx="2" /><path d="M8 21h8M12 17v4M7 9h3M7 12h6" /></>,
  settings: <><path d="M4 7h16M4 17h16" /><circle cx="9" cy="7" r="3" /><circle cx="15" cy="17" r="3" /></>,
  activity: <path d="M3 12h4l3-8 4 16 3-8h4" />,
}

export default function Icon({ name, className = '' }) {
  return <svg className={`ui-icon ${className}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name] || paths.shield}</svg>
}
