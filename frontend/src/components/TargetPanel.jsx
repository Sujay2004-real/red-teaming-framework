import ScopePolicy from './ScopePolicy'
import { useApp } from '../lib/AppContext'

// Registering an authorized target: the scope every command will be checked
// against comes from here (or from the imported letter), so the form is the
// authorization boundary the operator types into.
export default function TargetPanel({ target, setTarget, onAdd }) {
  const { busy, agentBusy } = useApp()
  return <section className="panel"><h2>Add authorized target</h2>
    <form onSubmit={onAdd}>
      <label>Display name<input required value={target.name} onChange={e => setTarget({ ...target, name: e.target.value })} placeholder="OmniRoute gateway" /></label>
      <label>Primary host or network (CIDR)<input required value={target.scope_domain_ip} onChange={e => setTarget({ ...target, scope_domain_ip: e.target.value })} placeholder="192.168.198.86:20128 or 192.168.198.0/24" /><small>CIDR targets run a live-host and common-port discovery sweep. Ranges are limited to 256 addresses per assessment.</small></label>
      <label>Allowed domains / CIDRs<input value={target.authorized_scopes} onChange={e => setTarget({ ...target, authorized_scopes: e.target.value })} placeholder="192.168.198.86, 192.168.198.0/24" /></label>
      <label>Asset criticality<input type="number" min="0" max="100" required value={target.criticality} onChange={e => setTarget({ ...target, criticality: e.target.value })} /><small>0-100. Feeds the priority score of every finding on this target.</small></label>
      <label className="check-row"><input type="checkbox" checked={!!target.exploitation_authorized} onChange={e => setTarget({ ...target, exploitation_authorized: e.target.checked, aggressive_lab: e.target.checked && target.aggressive_lab })} /><span>The client's letter authorizes controlled exploitation (verification) against this target</span></label>
      <small className="plan-note">Leave unchecked unless the letter explicitly authorizes controlled verification — the policy engine refuses every exploit-grade command otherwise.</small>
      <label className="check-row"><input type="checkbox" disabled={!target.exploitation_authorized} checked={!!target.aggressive_lab} onChange={e => setTarget({ ...target, aggressive_lab: e.target.checked })} /><span>Aggressive lab mode — weaponized exploitation (data dumping, single-command RCE, Metasploit exploit modules with payloads/sessions)</span></label>
      <small className="plan-note">Only for a lab target you fully own and are authorized to attack. It unlocks real impact beyond verification; every step still needs your per-step approval, and scope checks still apply. Requires controlled exploitation above; leave off for any production or client target.</small>
      <ScopePolicy value={target.engagement_policy || {}} onChange={engagement_policy => setTarget({ ...target, engagement_policy })} />
      <button disabled={busy}>{agentBusy('registrar') ? 'Registering…' : 'Add target'}</button>
    </form>
  </section>
}
