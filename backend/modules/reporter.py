from jinja2 import Environment, FileSystemLoader
import os
from typing import List, Dict, Any

class Reporter:
    def __init__(self):
        self.template_dir = os.path.join(os.path.dirname(__file__), "templates")
        if not os.path.exists(self.template_dir):
            os.makedirs(self.template_dir)
        self.env = Environment(loader=FileSystemLoader(self.template_dir))

    def generate_html_report(self, target: str, objective: str, findings: List[Dict[str, Any]], output_path: str):
        """
        Generates an HTML security report from the findings.
        """
        template = self.env.get_template("report_template.html")
        html_out = template.render(
            target=target,
            objective=objective,
            findings=findings,
            total_findings=len(findings)
        )
        
        with open(output_path, "w") as f:
            f.write(html_out)
        
        return output_path

reporter = Reporter()
