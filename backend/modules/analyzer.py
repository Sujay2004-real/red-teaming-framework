import hashlib
import json
import re

SEVERITY = {'Low': 25, 'Medium': 50, 'High': 75, 'Critical': 100}

def score_finding(finding):
    severity = finding.get('severity', 'Low').title()
    severity_score = SEVERITY.get(severity, 25)
    exploitability = max(1, min(5, int(finding.get('exploitability', 3))))
    impact = max(1, min(5, int(finding.get('impact', 3))))
    exposure = max(1, min(5, int(finding.get('exposure', 3))))
    confidence = max(0, min(100, int(finding.get('confidence_score', 70))))
    asset_criticality = max(0, min(100, int(finding.get('asset_criticality', 70))))
    risk = exploitability * impact * exposure
    priority = round(.40 * severity_score + .25 * exploitability * 20 + .20 * asset_criticality + .15 * confidence)
    return severity, risk, priority, confidence

def fingerprint(finding):
    material = '|'.join(str(finding.get(k, '')).lower().strip() for k in ('title', 'endpoint', 'parameter'))
    return hashlib.sha256(material.encode()).hexdigest()[:24]

class AnalyzerAgent:
    model_name = 'gpt-4o-mini'
    prompt_version = 'analyzer-v2'

    def _fallback(self, raw_outputs):
        findings = []
        patterns = [
            (r'\b(80|3000|8080)/tcp\s+open\b', 'Exposed HTTP service', 'Medium', 'Restrict network exposure and harden the web service.'),
            (r'\b22/tcp\s+open\b', 'Exposed SSH service', 'Medium', 'Restrict SSH access, require keys, and disable password login.'),
            (r'(?i)(xss|cross.site scripting)', 'Potential cross-site scripting', 'High', 'Apply contextual output encoding and a restrictive Content Security Policy.'),
            (r'(?i)(sql injection|sqli)', 'Potential SQL injection', 'Critical', 'Use parameterized queries and validate server-side input.'),
            (r'(?i)(missing.*security header|x-frame-options|content-security-policy)', 'Missing browser security headers', 'Low', 'Configure appropriate HTTP security headers.'),
        ]
        for output in raw_outputs:
            combined = f"{output.get('stdout','')}\n{output.get('stderr','')}"
            for pattern, title, severity, remediation in patterns:
                match = re.search(pattern, combined)
                if match:
                    findings.append({'title': title, 'description': f"{output.get('tool')} reported evidence matching a known security signal.", 'severity': severity, 'evidence': match.group(0), 'remediation': remediation, 'confidence_score': 65, 'source_tools': [output.get('tool')], 'exploitability': 3, 'impact': 3, 'exposure': 3})
        return findings

    def analyze_results(self, raw_outputs, api_key='', base_url='', model_name=''):
        findings = []
        if api_key and raw_outputs:
            try:
                import requests
                prompt = f'''Analyze these authorized scanner outputs and return only a JSON list. Each item: title, description, severity (Low/Medium/High/Critical), evidence, remediation, endpoint, parameter, exploitability (1-5), impact (1-5), exposure (1-5), confidence_score (0-100), source_tools. Outputs: {json.dumps(raw_outputs)}'''
                text = model.generate_content(prompt).text.strip().removeprefix('```json').removesuffix('```').strip()
                findings = json.loads(text)
            except Exception:
                findings = self._fallback(raw_outputs)
        else:
            findings = self._fallback(raw_outputs)
        merged = {}
        for item in findings:
            key = fingerprint(item)
            severity, risk, priority, confidence = score_finding(item)
            normalized = {**item, 'fingerprint': key, 'severity': severity, 'risk_score': risk, 'priority_score': priority, 'confidence_score': confidence, 'source_tools': item.get('source_tools') or []}
            if key in merged:
                merged[key]['source_tools'] = sorted(set(merged[key]['source_tools'] + normalized['source_tools']))
                merged[key]['evidence'] += '\n' + normalized.get('evidence', '')
                merged[key]['confidence_score'] = max(merged[key]['confidence_score'], confidence)
            else:
                merged[key] = normalized
        return list(merged.values())

analyzer_agent = AnalyzerAgent()
