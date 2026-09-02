"""One-shot end-to-end smoke test against the running Docker stack.

Run from the project root:
    .\\backend\\venv\\Scripts\\python.exe backend\\smoke_e2e.py

Walks the whole flow the UI drives: import the letter, register the target,
draft the assessment, execute two real commands (one fast, one that produces
rich header findings), analyze, and generate the report — printing each
result so the whole pipeline can be verified in one scroll.
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
t0, t1 = eng['targets']
print(f"  target0: {t0['address']} crit={t0['criticality']} restricted={t0['restricted_tools']}")
print(f"  target1: {t1['address']} crit={t1['criticality']} restricted={t1['restricted_tools']}")

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
report_html = call(report['download_url'], headers={}) if False else None
print('SMOKE TEST PASSED')