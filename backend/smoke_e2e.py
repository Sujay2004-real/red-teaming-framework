"""One-shot end-to-end smoke test against the running Docker stack.

Run from the project root:
    .\\backend\\venv\\Scripts\\python.exe backend\\smoke_e2e.py

Walks the whole flow the UI drives: import the letter, register the target,
draft the assessment, execute the plan, analyze, and generate the report —
printing each result so the whole pipeline can be verified in one scroll.

Every letter target now lives on the virtualization lab's host-only network
(storefront 192.168.56.10:3000, legacy server 192.168.56.20:80, segment
192.168.56.0/24), so the full walkthrough expects the lab VMs to be running.
Without them the commands still execute and record their exit codes — the
pipeline completes, it just gathers nothing from unreachable hosts.
"""
import json
import urllib.request

BASE = 'http://localhost:8000'
PDF = 'JuiceBox_Security_Assessment_Request.pdf'


def call(path, method='GET', body=None, headers=None, raw=None):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header('Content-Type', 'application/json')
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
t0, t1, t2 = eng['targets'][0], eng['targets'][1], eng['targets'][2]
print(f"  target0: {t0['address']} crit={t0['criticality']} restricted={t0['restricted_tools']}")
print(f"  target1: {t1['address']} crit={t1['criticality']} restricted={t1['restricted_tools']}")
print(f"  target2: {t2['address']} crit={t2['criticality']} restricted={t2['restricted_tools']}")

# 3. Register the primary target
target = call('/targets/', 'POST', {
    'name': t0['name'], 'scope_domain_ip': t0['address'],
    'authorized_scopes': t0['scopes'], 'criticality': t0['criticality'],
    'restricted_tools': t0['restricted_tools'],
})
print(f"registered target #{target['id']} restricted={target['restricted_tools']}")

# 4. Draft the assessment (deterministic plan, restricted steps dropped)
assessment = call('/assessments/', 'POST', {
    'target_id': target['id'], 'objective': f"Deep assessment per {eng['engagement_ref']}",
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

# 7. Analyze
analysis = call(f"/assessments/{assessment['id']}/analyze", 'POST')
print(f"analysis: {analysis['findings_count']} findings ({analysis['analyzer']} mode)")

detail = call(f"/assessments/{assessment['id']}")
for finding in detail['findings'][:8]:
    print(f"  [{finding['severity']:8}] {finding['title']} "
          f"(risk {finding['risk_score']}, priority {finding['priority_score']}, "
          f"via {','.join(finding['source_tools'])})")

# 8. Report
report = call(f"/assessments/{assessment['id']}/report", 'POST')
print(f"report: {report['download_url']}")

# 9. Subnet discovery sweep (the letter's third target). The plan is nmap-only
# because no other tool accepts a range, and the letter's deny-list for the
# segment independently reaches the same shape - both layers agree. The
# letter's segment (192.168.56.0/24) is the host-only network of the
# virtualization lab: with the lab VMs running the sweep finds them; in a
# Docker-only demo it may legitimately discover nothing, so the host-qualified
# findings assertion only runs when live hosts were found.
subnet_target = call('/targets/', 'POST', {
    'name': t2['name'], 'scope_domain_ip': t2['address'],
    'authorized_scopes': t2['scopes'], 'criticality': t2['criticality'],
    'restricted_tools': t2['restricted_tools'],
})
print(f"registered subnet target #{subnet_target['id']} address={t2['address']}")
subnet = call('/assessments/', 'POST', {
    'target_id': subnet_target['id'],
    'objective': f"Network segment discovery sweep per {eng['engagement_ref']} Section 3.3",
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
    print('  note: no live hosts on the segment - expected in a Docker-only demo '
          'without the virtualization lab VMs; host-attribution skipped')
subnet_report = call(f"/assessments/{subnet['id']}/report", 'POST')
print(f"subnet report: {subnet_report['download_url']}")
print('SMOKE TEST PASSED')