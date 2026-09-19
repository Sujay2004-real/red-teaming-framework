"""Quantitative evaluation harness for the framework.

Run (backend must be up, operator key in the environment):
    set REDTEAM_API_KEY=...  (or the generated key from the backend console)
    backend\\venv\\Scripts\\python.exe backend\\eval_harness.py [--runs N] [--targets a,b,...] [--out results.json]

WHAT IT MEASURES, PER RUN
  wall-clock phases   - seconds from target registration to report generation,
                        broken into planning / execution / analysis / reporting
  commands            - steps drafted vs executed, exit codes
  findings            - count, severity mix, dedup ratio (raw findings before
                        merge vs after), verification outcomes
  policy refusals     - none are expected on the happy path; any refusal is
                        recorded with its reason (the guardrail's receipt)
  provider mode       - deterministic fallback or ai-provider, so runs with
                        and without a provider are comparable side by side

WHY THESE NUMBERS
  The Phase-1 report's Chapter 8 compares the framework to manual testing,
  scanners and scripts qualitatively. This harness turns those claims into
  measurements: N runs against the same target produce a distribution, and
  the deterministic-vs-provider runs give the ablation the base paper
  (PentestGPT, Fig. 8) made its argument with.

GROUND TRUTH
  Against Metasploitable2 (or any target with documented vulnerabilities),
  the ground-truth checklist can be supplied via --checklist <file> (one
  expected finding title or service per line). Recall is then the share of
  checklist lines matched by any finding title/endpoint (case-insensitive
  substring). Without a checklist, the harness still reports everything else.
"""
import argparse
import json
import os
import statistics
import time
import urllib.error
import urllib.request

BASE = os.getenv('EVAL_BASE_URL', 'http://localhost:8000')
API_KEY = os.getenv('REDTEAM_API_KEY', '')


def call(path, method='GET', body=None, headers=None, raw=None, timeout=400):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header('Content-Type', 'application/json')
    if API_KEY:
        req.add_header('X-API-Key', API_KEY)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    with urllib.request.urlopen(req, timeout=timeout) as res:
        return json.loads(res.read().decode())


def upload_letter(pdf_path):
    boundary = '----evalboundary'
    with open(pdf_path, 'rb') as stream:
        pdf_bytes = stream.read()
    multipart = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
        f'filename="{os.path.basename(pdf_path)}"\r\nContent-Type: application/pdf\r\n\r\n'
    ).encode() + pdf_bytes + f'\r\n--{boundary}--\r\n'.encode()
    return call('/engagement/parse', 'POST', raw=multipart,
                headers={'Content-Type': f'multipart/form-data; boundary={boundary}'})


def run_one_engagement(target_spec, run_index, letter_pdf=None, checklist=None):
    """Drive one full phased engagement and return its measurements.

    target_spec: dict with name, scope_domain_ip, authorized_scopes,
    criticality, restricted_tools, exploitation_authorized - the same shape
    the UI's "Add authorized target" panel sends.
    """
    timings = {}
    record = {'run': run_index, 'target': target_spec['scope_domain_ip'],
              'objective': target_spec.get('objective', 'Evaluation run'),
              'commands': {'drafted': 0, 'executed': 0, 'failed': []},
              'findings': {}, 'refusals': [], 'phases': []}

    t0 = time.perf_counter()
    target = call('/targets/', 'POST', {
        'name': target_spec['name'], 'scope_domain_ip': target_spec['scope_domain_ip'],
        'authorized_scopes': target_spec['authorized_scopes'],
        'criticality': target_spec.get('criticality', 70),
        'restricted_tools': target_spec.get('restricted_tools', []),
        'exploitation_authorized': bool(target_spec.get('exploitation_authorized', False)),
    })
    payload = {'target_id': target['id'], 'objective': target_spec.get('objective', 'Evaluation run')}
    if letter_pdf and os.path.exists(letter_pdf):
        payload['engagement_brief'] = {'targets': [target_spec]}
    assessment = call('/assessments/', 'POST', payload)
    timings['planning_s'] = round(time.perf_counter() - t0, 2)
    record['commands']['drafted'] = len(assessment['plan'])
    record['plan_source'] = assessment.get('plan_source', '')

    # Walk every plan phase: execute enabled steps, analyze, draft the next
    # phase when the letter allows it, repeat until reporting.
    phase_guard = 0
    while phase_guard < 6:
        phase_guard += 1
        detail = call(f"/assessments/{assessment['id']}")
        current_phase = detail['current_phase'] or 'recon'
        plan = detail['plan']
        phase_steps = [(i, s) for i, s in enumerate(plan)
                       if s.get('phase', 'recon') == current_phase and s.get('enabled', True)]
        if not phase_steps:
            break
        t_exec = time.perf_counter()
        for index, step in phase_steps:
            try:
                result = call(f"/assessments/{assessment['id']}/execute", 'POST',
                              {'step_index': index, 'approved': True})
                record['commands']['executed'] += 1
                r = result['result']
                if r['return_code'] != 0:
                    record['commands']['failed'].append(
                        {'tool': step['tool'], 'return_code': r['return_code'],
                         'command': step['command'][:200]})
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode(errors='ignore')[:300]
                record['refusals'].append({'tool': step.get('tool'), 'status': exc.code,
                                           'detail': detail})
        record['phases'].append({'phase': 'execute', 'seconds': round(time.perf_counter() - t_exec, 2)})

        t_an = time.perf_counter()
        analysis = call(f"/assessments/{assessment['id']}/analyze", 'POST')
        record['phases'].append({'phase': 'analyze', 'seconds': round(time.perf_counter() - t_an, 2)})
        record['findings'].setdefault('per_phase', []).append(
            {'phase': analysis['phase'], 'count': analysis['findings_count'],
             'verified': analysis.get('verified_findings', 0)})
        record['analyzer'] = analysis.get('analyzer', '')

        current = analysis['current_phase']
        if current == 'reporting':
            break
        try:
            call(f"/assessments/{assessment['id']}/phases/{current}/plan", 'POST')
        except urllib.error.HTTPError:
            # Nothing draftable (clean target, unauthorized exploitation) - the
            # engagement has nothing further to verify.
            break

    t_rep = time.perf_counter()
    call(f"/assessments/{assessment['id']}/report", 'POST')
    timings['reporting_s'] = round(time.perf_counter() - t_rep, 2)

    detail = call(f"/assessments/{assessment['id']}")
    findings = detail['findings']
    record['findings']['total'] = len(findings)
    record['findings']['severity'] = {
        level: sum(1 for f in findings if f['severity'] == level)
        for level in ('Critical', 'High', 'Medium', 'Low')}
    record['findings']['verified'] = sum(1 for f in findings if f.get('verification') == 'verified')
    record['findings']['attempted'] = sum(1 for f in findings if f.get('verification') == 'attempted')
    record['findings']['tools'] = sorted({tool for f in findings for tool in (f.get('source_tools') or [])})

    if checklist:
        from modules.eval_metrics import evaluate
        record['checklist'] = evaluate(findings, checklist)

    timings['total_s'] = round(time.perf_counter() - t0, 2)
    timings['execution_s'] = round(sum(p['seconds'] for p in record['phases']
                                       if p['phase'] == 'execute'), 2)
    timings['analysis_s'] = round(sum(p['seconds'] for p in record['phases']
                                      if p['phase'] == 'analyze'), 2)
    record['timings'] = timings
    record['assessment_id'] = assessment['id']
    return record


def summarize(runs):
    """Distribution summary across runs: mean and stdev per metric."""
    def series(fn):
        values = [fn(r) for r in runs]
        return {'mean': round(statistics.mean(values), 2),
                'stdev': round(statistics.stdev(values), 2) if len(values) > 1 else 0.0,
                'min': round(min(values), 2), 'max': round(max(values), 2)}

    summary = {
        'runs': len(runs),
        'analyzer_modes': sorted({r.get('analyzer', '') for r in runs}),
        'wall_clock_total_s': series(lambda r: r['timings']['total_s']),
        'execution_s': series(lambda r: r['timings'].get('execution_s', 0)),
        'analysis_s': series(lambda r: r['timings'].get('analysis_s', 0)),
        'planning_s': series(lambda r: r['timings']['planning_s']),
        'reporting_s': series(lambda r: r['timings'].get('reporting_s', 0)),
        'commands_executed': series(lambda r: r['commands']['executed']),
        'commands_failed': series(lambda r: len(r['commands']['failed'])),
        'findings_total': series(lambda r: r['findings']['total']),
        'findings_verified': series(lambda r: r['findings'].get('verified', 0)),
    }
    recalls = [r['checklist']['recall'] for r in runs if r.get('checklist')]
    if recalls:
        summary['checklist_recall'] = series(lambda _: 0)  # placeholder replaced below
        summary['checklist_recall'] = {
            'mean': round(statistics.mean(recalls), 3),
            'stdev': round(statistics.stdev(recalls), 3) if len(recalls) > 1 else 0.0,
            'min': min(recalls), 'max': max(recalls)}
    return summary


def provider_state():
    """The current provider configuration, for the ablation mode.

    GET /settings returns everything needed to disable and later restore the
    provider (the API key itself is write-only and never leaves the backend,
    which is exactly what the ablation needs: disable = clear the endpoint,
    restore = put the endpoint back; the stored key is untouched either way).
    """
    return call('/settings')


def set_provider_endpoint(base_url, model_name):
    call('/settings', 'PUT', {'api_base_url': base_url, 'model_name': model_name})


def run_ablation(targets, runs, letter, checklist):
    """Deterministic vs AI provider: the same engagement, both analyzers.

    The PentestGPT paper made its argument with an ablation (its Fig. 8:
    which module contributes what). This is the same shape applied here: the
    identical target and run count, once with the configured provider driving
    planning/analysis and once on the deterministic path. The provider's
    stored key is never touched - disabling means clearing the endpoint,
    which is reversible, and restoring means putting it back.
    """
    settings = provider_state()
    if not settings.get('provider_ready'):
        print('No AI provider is configured; both arms would run deterministic. '
              'Configure the provider in the UI first, then re-run with --ablate.')
        return None
    saved = {'base_url': settings['api_base_url'], 'model': settings['model_name']}

    try:
        print('== arm 1: deterministic (provider endpoint cleared) ==')
        set_provider_endpoint('', saved['model'])
        det_runs = []
        for spec in targets:
            for run_index in range(1, runs + 1):
                print(f"  run {run_index}/{runs} against {spec['scope_domain_ip']} ...", flush=True)
                try:
                    det_runs.append(run_one_engagement(spec, run_index, letter, checklist))
                except Exception as exc:  # noqa: BLE001 - a failed run is a result too
                    det_runs.append({'run': run_index, 'target': spec['scope_domain_ip'],
                                     'error': f'{type(exc).__name__}: {exc}'})

    finally:
        set_provider_endpoint(saved['base_url'], saved['model'])

    print('== arm 2: AI provider (endpoint restored) ==')
    set_provider_endpoint(saved['base_url'], saved['model'])
    ai_runs = []
    for spec in targets:
        for run_index in range(1, runs + 1):
            print(f"  run {run_index}/{runs} against {spec['scope_domain_ip']} ...", flush=True)
            try:
                ai_runs.append(run_one_engagement(spec, run_index, letter, checklist))
            except Exception as exc:  # noqa: BLE001
                ai_runs.append({'run': run_index, 'target': spec['scope_domain_ip'],
                                'error': f'{type(exc).__name__}: {exc}'})

    ok_det = [r for r in det_runs if 'error' not in r]
    ok_ai = [r for r in ai_runs if 'error' not in r and r.get('analyzer') == 'ai-provider']
    return {
        'deterministic': {'runs': det_runs, 'summary': summarize(ok_det) if ok_det else {}},
        'ai-provider': {'runs': ai_runs, 'summary': summarize(ok_ai) if ok_ai else {}},
        'provider_fallback_runs': [r for r in ai_runs if r.get('analyzer') != 'ai-provider'],
        'comparison': {
            'modes': sorted({r.get('analyzer', '') for r in ok_det + ok_ai}),
            'findings_mean': {
                'deterministic': round(statistics.mean([r['findings']['total'] for r in ok_det]), 2) if ok_det else None,
                'ai-provider': round(statistics.mean([r['findings']['total'] for r in ok_ai]), 2) if ok_ai else None,
            },
            'wall_clock_mean_s': {
                'deterministic': round(statistics.mean([r['timings']['total_s'] for r in ok_det]), 2) if ok_det else None,
                'ai-provider': round(statistics.mean([r['timings']['total_s'] for r in ok_ai]), 2) if ok_ai else None,
            },
            'recall_mean': {
                'deterministic': round(statistics.mean([r['checklist']['recall'] for r in ok_det if r.get('checklist')]), 3)
                if any(r.get('checklist') for r in ok_det) else None,
                'ai-provider': round(statistics.mean([r['checklist']['recall'] for r in ok_ai if r.get('checklist')]), 3)
                if any(r.get('checklist') for r in ok_ai) else None,
            },
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--runs', type=int, default=3, help='runs per target (default 3)')
    parser.add_argument('--targets', type=str, default='',
                        help='comma-separated target specs NAME=HOST[:PORT] (e.g. "Meta2=192.168.56.101")')
    parser.add_argument('--letter', type=str, default='', help='engagement letter PDF to import for context')
    parser.add_argument('--checklist', type=str, default='',
                        help='ground-truth file: one expected finding/service per line')
    parser.add_argument('--exploit', action='store_true',
                        help='targets authorize controlled exploitation (lab targets only)')
    parser.add_argument('--ablate', action='store_true',
                        help='run each arm twice: deterministic analyzer, then the configured AI provider '
                             '(the PentestGPT-style ablation; provider must be configured in the UI first)')
    parser.add_argument('--out', type=str, default='eval_results.json', help='output JSON path')
    args = parser.parse_args()

    checklist = None
    if args.checklist and os.path.exists(args.checklist):
        with open(args.checklist, encoding='utf-8') as stream:
            checklist = json.load(stream) if args.checklist.endswith('.json') else stream.read().splitlines()

    targets = []
    if args.targets:
        for item in args.targets.split(','):
            name, _, address = item.partition('=')
            name, address = (name or address).strip(), (address or name).strip()
            targets.append({
                'name': name, 'scope_domain_ip': address,
                'authorized_scopes': [address], 'criticality': 40,
                'exploitation_authorized': args.exploit,
                'objective': f'Full phased evaluation of {name}',
            })
    elif args.letter and os.path.exists(args.letter):
        brief = upload_letter(args.letter)
        for t in brief['engagement']['targets']:
            targets.append({
                'name': t['name'] or t['address'], 'scope_domain_ip': t['address'],
                'authorized_scopes': t['scopes'] or [t['address']],
                'criticality': t.get('criticality', 70),
                'restricted_tools': t.get('restricted_tools', []),
                'exploitation_authorized': t.get('exploitation_authorized', False),
                'objective': f"Deep assessment per {brief['engagement']['engagement_ref']}",
            })
    else:
        parser.error('give --targets NAME=HOST or --letter <pdf>')

    if args.ablate:
        report = run_ablation(targets, args.runs, args.letter, checklist)
        if report is None:
            return
    else:
        all_runs = []
        for spec in targets:
            for run_index in range(1, args.runs + 1):
                print(f"run {run_index}/{args.runs} against {spec['scope_domain_ip']} ...", flush=True)
                try:
                    record = run_one_engagement(spec, run_index, args.letter, checklist)
                except Exception as exc:  # noqa: BLE001 - a failed run is a result too
                    record = {'run': run_index, 'target': spec['scope_domain_ip'],
                              'error': f'{type(exc).__name__}: {exc}'}
                all_runs.append(record)
                print('   ', json.dumps({k: v for k, v in record.items()
                                         if k in ('timings', 'findings', 'error')}))
        ok_runs = [r for r in all_runs if 'error' not in r]
        report = {'runs': all_runs, 'summary': summarize(ok_runs) if ok_runs else {}}

    with open(args.out, 'w', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
    print(f"\nresults -> {args.out}")
    print(json.dumps(report.get('summary') or report.get('comparison') or {}, indent=2))


if __name__ == '__main__':
    main()
