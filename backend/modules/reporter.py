from jinja2 import Environment, FileSystemLoader, select_autoescape
import os

class Reporter:
    def __init__(self):
        self.template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        self.env = Environment(loader=FileSystemLoader(self.template_dir), autoescape=select_autoescape(['html']))

    def generate_html_report(self, target, objective, findings, executions, output_path, engagement_brief=None, analysis_mode=''):
        template = self.env.get_template('report_template.html')
        severity_counts = {level: sum(1 for f in findings if f.get('severity') == level) for level in ('Critical','High','Medium','Low')}
        # Only the facts a report reader needs from the letter: who asked for
        # the work, under which reference, and what they ruled out. The raw
        # letter text stays out of the deliverable.
        brief = engagement_brief if isinstance(engagement_brief, dict) else {}
        engagement = {
            'client_name': brief.get('client_name') or '',
            'engagement_ref': brief.get('engagement_ref') or '',
            'test_window': brief.get('test_window') or '',
            'objectives': [str(o) for o in (brief.get('objectives') or [])][:20],
            'out_of_scope': [str(o) for o in (brief.get('out_of_scope') or [])][:20],
            'prohibited': [str(o) for o in (brief.get('prohibited') or [])][:20],
        }
        html = template.render(target=target, objective=objective, findings=findings, executions=executions, total_findings=len(findings), severity_counts=severity_counts, engagement=engagement, analysis_mode=analysis_mode or '')
        with open(output_path, 'w', encoding='utf-8') as stream:
            stream.write(html)
        return output_path

reporter = Reporter()
