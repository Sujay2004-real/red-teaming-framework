export default function ScopePolicy({ value = {}, onChange, readOnly = false }) {
  const patch = (key, next) => onChange({ ...value, [key]: next })
  if (readOnly) return <dl className="scope-summary"><dt>Excluded scopes</dt><dd>{value.excluded_scopes?.join(', ') || 'None recorded'}</dd><dt>Test window</dt><dd>{value.starts_at || 'No start set'} → {value.ends_at || 'No end set'}</dd><dt>Budget</dt><dd>{value.max_executions || 100} attempts per assessment; {value.max_rate || 30} requests or packets/s for rate-capable scanners</dd><dt>Prohibited tools</dt><dd>{value.prohibited_tools?.join(', ') || 'None recorded'}</dd></dl>
  return <fieldset className="scope-fields"><legend>Enforced rules</legend>
    <label>Excluded hosts, URLs, or CIDRs<textarea rows="2" value={(value.excluded_scopes || []).join('\n')} onChange={e => patch('excluded_scopes', e.target.value.split('\n'))} placeholder="One exclusion per line" /></label>
    <label>Prohibited tools<input value={(value.prohibited_tools || []).join(',')} onChange={e => patch('prohibited_tools', e.target.value.split(',').map(x => x.trim()).filter(Boolean))} placeholder="sqlmap, msfconsole" /></label>
    <div className="split"><label>Start (UTC)<input type="datetime-local" value={value.starts_at?.slice(0, 16) || ''} onChange={e => patch('starts_at', e.target.value ? e.target.value + ':00Z' : null)} /></label><label>End (UTC)<input type="datetime-local" value={value.ends_at?.slice(0, 16) || ''} onChange={e => patch('ends_at', e.target.value ? e.target.value + ':00Z' : null)} /></label></div>
    <div className="split"><label>Maximum attempts<input type="number" min="1" max="1000" value={value.max_executions ?? 100} onChange={e => patch('max_executions', Number(e.target.value))} /></label><label>Scanner rate limit<input type="number" min="1" max="30" value={value.max_rate ?? 30} onChange={e => patch('max_rate', Number(e.target.value))} /></label></div>
    <label>Reviewed restrictions and notes<textarea rows="3" value={value.review_notes || ''} onChange={e => patch('review_notes', e.target.value)} /></label>
    <small>Hosts match exactly. Use *.example.com to authorize subdomains. URL scopes preserve their scheme, port, and path. Scanner rate flags must stay within this limit.</small>
  </fieldset>
}
