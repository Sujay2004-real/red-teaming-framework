from jinja2 import Environment, FileSystemLoader, select_autoescape
import os

class Reporter:
    def __init__(self):
        self.template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        self.env = Environment(loader=FileSystemLoader(self.template_dir), autoescape=select_autoescape(['html']))

    def generate_html_report(self, target, objective, findings, executions, output_path):
        template = self.env.get_template('report_template.html')
        severity_counts = {level: sum(1 for f in findings if f.get('severity') == level) for level in ('Critical','High','Medium','Low')}
        html = template.render(target=target, objective=objective, findings=findings, executions=executions, total_findings=len(findings), severity_counts=severity_counts)
        with open(output_path, 'w', encoding='utf-8') as stream:
            stream.write(html)
        return output_path

reporter = Reporter()
