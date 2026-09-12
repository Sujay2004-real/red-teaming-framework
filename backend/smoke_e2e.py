"""One-shot end-to-end smoke test against the running backend.

Run from the project root:
    .\\backend\\venv\\Scripts\\python.exe backend\\smoke_e2e.py

Walks the whole phased flow the UI drives: import the letter, register the
target, draft the assessment, execute the recon plan, analyze, draft the
exploitation plan from the findings, execute it, analyze (verification),
draft the bounded post-exploitation plan, and generate the report — printing
each result so the whole pipeline can be verified in one scroll.

The letter (v7) assesses a real self-hosted application: the OmniRoute AI
gateway on the assessment host (192.168.198.86:20128 on the lab LAN), plus a
discovery sweep of the 192.168.198.0/24 segment. Without
the lab running, the commands still execute and record their exit codes —
the pipeline completes, it just gathers nothing from unreachable hosts. The
letter authorizes controlled verification for the gateway, so the
exploitation phase runs there; against a real application the PoCs are
expected to come back clean (attempted, not confirmed).
"""
import json
import os
import urllib.request

BASE = os.getenv('SMOKE_BASE_URL', 'http://localhost:8000')
PDF = 'JuiceBox_Security_Assessment_Request.pdf'
# Every route but /health requires the operator key. REDTEAM_API_KEY (set in
# the backend's environment) is the scripted path; a backend started without
# it printed a generated key to its console on first start.
API_KEY = os.getenv('REDTEAM_API_KEY', '')


def call(path, method='GET', body=None, headers=None, raw=None):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header('Content-Type', 'application/json')
    if API_KEY:
        req.add_header('X-API-Key', API_KEY)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    # Above the executor's 360 s cap (the plan's nuclei step alone runs ~310 s),
    # so the server always decides how a command ends.
    with urllib.request.urlopen(req, timeout=400) as res:
        return json.loads(res.read().decode())


# 1. Health
print('health:', call('/health'))

# 2. Import the letter (multipart upload)
boundary = '----smokeboundary'
with open(PDF, 'rb') as stream:
    pdf_bytes = stream.read()
multipart = (
    f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
    f'filename="{PDF}"\r\nContent-Type: application/pdf\r\n\r\n'
).encode() + pdf_bytes + f'\r\n--{boundary}--\r\n'.encode()
brief = call('/engagement/parse', 'POST', raw=multipart,
             headers={'Content-Type': f'multipart/form-data; boundary={boundary}'})
eng = brief['engagement']
print(f"letter: {eng['client_name']} | {eng['engagement_ref']} | "
      f"{len(eng['targets'])} targets | {len(eng['objectives'])} objectives")
t0, t1 = eng['targets'][0], eng['targets'][1]
print(f"  target0: {t0['address']} crit={t0['criticality']} restricted={t0['restricted_tools']}")
print(f"  target1: {t1['address']} crit={t1['criticality']} restricted={t1['restricted_tools']}")

# 3. Register the primary target
target = call('/targets/', 'POST', {
    'name': t0['name'], 'scope_domain_ip': t0['address'],
    'authorized_scopes': t0['scopes'], 'criticality': t0['criticality'],
    'restricted_tools': t0['restricted_tools'],
    'exploitation_authorized': t0.get('exploitation_authorized', False),
})
print(f"registered target #{target['id']} restricted={target['restricted_tools']} "
      f"exploitation_authorized={target['exploitation_authorized']}")

# 4. Draft the assessment (deterministic plan, restricted steps dropped).
# The engagement brief is attached so the exploit planner can read the
# letter's verification endpoints for the gateway.
assessment = call('/assessments/', 'POST', {
    'target_id': target['id'], 'objective': f"Deep assessment per {eng['engagement_ref']}",
    'engagement_brief': {'targets': eng['targets']},
})
print(f"assessment #{assessment['id']}: plan_source={assessment['plan_source']} "
      f"steps={len(assessment['plan'])} dropped={assessment['restricted_steps_dropped']}")
for step in assessment['plan']:
    print(f"  [{step['tool']}] {step['command']}")

# 5-6. Execute every enabled step in order, exactly as the UI's operator
# would approve them one by one. Failed steps (e.g. sslscan against an
# HTTP-only host) still record a return code and count toward completion.
for index, step in enumerate(assessment['plan']):
    if step.get('enabled', True) is False:
        continue
    result = call(f"/assessments/{assessment['id']}/execute", 'POST',
                  {'step_index': index, 'approved': True})
    r = result['result']
    print(f"executed [{step['tool']}]: exit={r['return_code']} in {r['duration_ms']}ms")
    if step['tool'] == 'nmap':
        for line in r['stdout'].splitlines():
            if '/tcp' in line and 'open' in line:
                print('  service:', line.strip())
    if step['tool'] == 'curl' and r['return_code'] == 0:
        print('  headers seen:', r['stdout'][:200].replace(chr(10), ' | '))

# 7. Analyze (recon phase). The analysis also AUTO-DRAFTS the next phase's
# plan (the recommendation loop's Level 1): the response says so, and the
# drafted steps are already in the plan.
analysis = call(f"/assessments/{assessment['id']}/analyze", 'POST')
print(f"analysis: {analysis['findings_count']} findings ({analysis['analyzer']} mode), "
      f"phase {analysis['phase']} -> {analysis['current_phase']}")
auto = analysis.get('auto_drafted') or {}
print(f"auto-drafted: phase={auto.get('phase')} steps={auto.get('steps')} "
      f"note={auto.get('note') or '-'}")

detail = call(f"/assessments/{assessment['id']}")
for finding in detail['findings'][:8]:
    print(f"  [{finding['severity']:8}] {finding['title']} "
          f"(risk {finding['risk_score']}, priority {finding['priority_score']}, "
          f"via {','.join(finding['source_tools'])})")

# 7.5 Exploitation phase: the letter authorizes controlled verification for
# the gateway (exploitation_authorized=True from the parser), so the
# auto-draft above already produced verification steps FROM the findings: the
# sqlmap verification of the web endpoint plus the letter's curl
# proof-of-concept; msfconsole steps appear only when nmap saw a scannable
# service, and they refuse to run in local mode (VM-only) - that refusal is
# expected and recorded, so the phase still completes. Against a real,
# maintained application the PoCs are expected to verify clean.
drafted = detail
print(f"exploitation plan: {sum(1 for s in drafted['plan'] if s.get('phase') == 'exploitation')} steps "
      f"(auto-drafted from the findings)")
for step in drafted['plan']:
    if step.get('phase') == 'exploitation':
        print(f"  [{step['tool']}] {step['command']}")

for index, step in enumerate(drafted['plan']):
    if step.get('phase') != 'exploitation':
        continue
    result = call(f"/assessments/{assessment['id']}/execute", 'POST',
                  {'step_index': index, 'approved': True})
    r = result['result']
    note = ''
    if step['tool'] == 'msfconsole':
        note = ' (VM-only; refused in local mode as designed)' if r['return_code'] != 0 else ''
    print(f"executed [{step['tool']}]: exit={r['return_code']} in {r['duration_ms']}ms{note}")

# 7.6 Analyze the exploitation phase: verified findings carry the proof, and
# the analysis auto-drafts the bounded post-exploitation plan.
exploit_analysis = call(f"/assessments/{assessment['id']}/analyze", 'POST')
print(f"exploitation analysis: {exploit_analysis['findings_count']} findings, "
      f"{exploit_analysis['verified_findings']} verified, "
      f"phase -> {exploit_analysis['current_phase']}, "
      f"auto-drafted {exploit_analysis['auto_drafted']['steps']} post-exploitation steps")
detail = call(f"/assessments/{assessment['id']}")
for finding in detail['findings']:
    if finding.get('verification'):
        print(f"  VERIFIED [{finding['severity']:8}] {finding['title'][:60]} "
              f"(by {','.join(finding.get('verified_by') or [])})")

# 7.7 Post-exploitation phase: bounded impact proof (DBMS banner, current
# user) for the verified injection points — the single record the letter
# permits per flaw. Auto-drafted by the exploitation analysis above.
post_draft = detail
print(f"post-exploitation plan: {sum(1 for s in post_draft['plan'] if s.get('phase') == 'post_exploitation')} steps")
for step in post_draft['plan']:
    if step.get('phase') == 'post_exploitation':
        print(f"  [{step['tool']}] {step['command']}")
for index, step in enumerate(post_draft['plan']):
    if step.get('phase') != 'post_exploitation':
        continue
    result = call(f"/assessments/{assessment['id']}/execute", 'POST',
                  {'step_index': index, 'approved': True})
    r = result['result']
    print(f"executed [{step['tool']}]: exit={r['return_code']} in {r['duration_ms']}ms")
post_analysis = call(f"/assessments/{assessment['id']}/analyze", 'POST')
print(f"post-exploitation analysis: phase -> {post_analysis['current_phase']}")

# 8. Report
report = call(f"/assessments/{assessment['id']}/report", 'POST')
print(f"report: {report['download_url']}")

# 9. Subnet discovery sweep (the letter's second target). The plan is nmap-only
# because no other tool accepts a range, and the letter's deny-list for the
# segment independently reaches the same shape - both layers agree. The
# letter's segment (192.168.198.0/24) is the host-only network of the
# virtualization lab: with the lab VMs running the sweep finds them; in a
# backend-only demo it may legitimately discover nothing, so the host-qualified
# findings assertion only runs when live hosts were found.
subnet_target = call('/targets/', 'POST', {
    'name': t1['name'], 'scope_domain_ip': t1['address'],
    'authorized_scopes': t1['scopes'], 'criticality': t1['criticality'],
    'restricted_tools': t1['restricted_tools'],
})
print(f"registered subnet target #{subnet_target['id']} address={t1['address']}")
subnet = call('/assessments/', 'POST', {
    'target_id': subnet_target['id'],
    'objective': f"Network segment discovery sweep per {eng['engagement_ref']} Section 3.2",
})
print(f"subnet assessment #{subnet['id']}: steps={len(subnet['plan'])} "
      f"dropped={subnet['restricted_steps_dropped']}")
for step in subnet['plan']:
    print(f"  [{step['tool']}] {step['command']}")
assert len(subnet['plan']) == 2, 'a CIDR target must yield the 2-step discovery sweep'
live_hosts = []
for index, step in enumerate(subnet['plan']):
    result = call(f"/assessments/{subnet['id']}/execute", 'POST',
                  {'step_index': index, 'approved': True})
    r = result['result']
    print(f"executed [{step['tool']}]: exit={r['return_code']} in {r['duration_ms']}ms")
    hosts = [line.split()[-1] for line in r['stdout'].splitlines()
             if line.startswith('Nmap scan report for')]
    if hosts:
        print('  live hosts:', ', '.join(hosts))
    for host in hosts:
        if host not in live_hosts:
            live_hosts.append(host)

subnet_analysis = call(f"/assessments/{subnet['id']}/analyze", 'POST')
print(f"subnet analysis: {subnet_analysis['findings_count']} findings "
      f"({subnet_analysis['analyzer']} mode)")
subnet_detail = call(f"/assessments/{subnet['id']}")
for finding in subnet_detail['findings'][:10]:
    print(f"  [{finding['severity']:8}] {finding['title']} @ {finding['endpoint']}")
if live_hosts:
    # Findings from a sweep must name the host they came from, not just the port.
    assert any(':' in f['endpoint'] and '/tcp' in f['endpoint'] for f in subnet_detail['findings']), \
        'sweep findings must be attributed to individual hosts'
else:
    print('  note: no live hosts on the segment - expected in a backend-only demo '
          'without the virtualization lab VMs; host-attribution skipped')
subnet_report = call(f"/assessments/{subnet['id']}/report", 'POST')
print(f"subnet report: {subnet_report['download_url']}")
print('SMOKE TEST PASSED')