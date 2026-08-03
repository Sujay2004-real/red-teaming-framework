import os
import json
import google.generativeai as genai
from typing import List, Dict, Any
from dotenv import load_dotenv

load_dotenv()

genai.configure(api_key=os.getenv("GEMINI_API_KEY", ""))

class AnalyzerAgent:
    def __init__(self):
        self.model = genai.GenerativeModel('gemini-1.5-pro')

    def analyze_results(self, raw_outputs: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """
        Analyzes raw tool outputs using Gemini.
        Returns a list of structured findings.
        """
        prompt = f"""
        You are an expert cybersecurity Red Team Analyst. 
        Analyze the following raw outputs from security scanning tools.
        
        Raw Outputs:
        {json.dumps(raw_outputs, indent=2)}

        Identify all valid security findings. Correlate similar findings and remove duplicates.
        Output the results STRICTLY as a JSON list of objects. Each object must have:
        - "title": Short descriptive title of the vulnerability.
        - "description": Detailed explanation of the finding.
        - "severity": "Low", "Medium", "High", or "Critical".
        - "evidence": The specific snippet from the tool output proving the vulnerability.
        - "remediation": Actionable steps to fix the issue.

        Do not use markdown formatting around the JSON output, just output the raw JSON array.
        """
        
        try:
            response = self.model.generate_content(prompt)
            text = response.text.strip()
            if text.startswith("```json"):
                text = text[7:]
            if text.endswith("```"):
                text = text[:-3]
            
            findings = json.loads(text)
            return findings
        except Exception as e:
            print(f"Error analyzing results: {e}")
            return []

analyzer_agent = AnalyzerAgent()
