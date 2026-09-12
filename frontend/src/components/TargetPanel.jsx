import { useApp } from '../lib/AppContext'

// Registering an authorized target: the scope every command will be checked
// against comes from here (or from the imported letter), so the form is the
// authorization boundary the operator types into.
export default function TargetPanel({ target, setTarget, onAdd }) {
  const { busy, agentBusy } = useApp()
  return <section className="panel"><h2>Add authorized target</h2>
    <form onSubmit={onAdd}>
      <label>Display name<input required value={target.name} onChange={e => setTarget({ ...target, name: e.target.value })} placeholder="Juice Shop lab" /></label>
      <label>Primary host or network (CIDR)<input required value={target.scope_domain_ip} onChange={e => setTarget({ ...target, scope_domain_ip: e.target.value })} placeholder="192.168.56.10:3000, 192.168.56.20:80 or 192.168.56.0/24" /><small>CIDR targets run a live-host and common-port discovery sweep. Ranges are limited to 256 addresses per assessment.</small></label>
      <label>Allowed domains / CIDRs<input value={target.authorized_scopes} onChange={e => setTarget({ ...target, authorized_scopes: e.target.value })} placeholder="192.168.56.10, 192.168.56.0/24" /></label>
      <label>Asset criticality<input type="number" min="0" max="100" required value={target.criticality} onChange={e => setTarget({ ...target, criticality: e.target.value })} /><small>0-100. Feeds the priority score of every finding on this target.</small></label>
      <label className="check-row"><input type="checkbox" checked={!!target.exploitation_authorized} onChange={e => setTarget({ ...target, exploitation_authorized: e.target.checked })} /><span>The client's letter authorizes controlled exploitation (verification) against this target</span></label>
      <small className="plan-note">Leave unchecked unless the letter explicitly authorizes controlled verification — the policy engine refuses every exploit-grade command otherwise.</small>
      <button disabled={busy}>{agentBusy('registrar') ? 'Registering…' : 'Add target'}</button>
    </form>
  </section>
}
