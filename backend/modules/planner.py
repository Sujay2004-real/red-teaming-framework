import os
import json
import google.generativeai as genai
from typing import List, Dict, Any
from dotenv import load_dotenv

load_dotenv()

# Configure Gemini API
genai.configure(api_key=os.getenv("GEMINI_API_KEY", ""))

class PlannerAgent:
    def __init__(self):
        # We use a chat model
        self.model = genai.GenerativeModel('gemini-1.5-pro')

    def generate_plan(self, target: str, objective: str, previous_findings: str = "") -> List[Dict[str, Any]]:
        """
        Generates a test plan using Gemini.
        Returns a list of steps, each containing 'tool', 'command', and 'reason'.
        """
        prompt = f"""
        You are an expert cybersecurity Red Team planner. Your task is to generate a semi-autonomous testing plan.
        Target: {target}
        Objective: {objective}
        Previous Findings: {previous_findings}

        Available tools: nmap, nuclei, zap-cli

        Output the plan STRICTLY as a JSON list of objects. Each object must have:
        - "tool": The name of the tool (nmap, nuclei, or zap-cli)
        - "command": The exact command to run (e.g. "nmap -sV {target}")
        - "reason": Why this step is necessary.

        Ensure commands do not use dangerous shell characters (|, &, ;, >, <, $, `).
        Do not use markdown formatting around the JSON output, just output the raw JSON array.
        """
        
        try:
            response = self.model.generate_content(prompt)
            # Try to parse the output
            text = response.text.strip()
            # Clean up markdown block if present
            if text.startswith("```json"):
                text = text[7:]
            if text.endswith("```"):
                text = text[:-3]
            
            plan = json.loads(text)
            return plan
        except Exception as e:
            print(f"Error generating plan: {e}")
            return [{"tool": "nmap", "command": f"nmap -sV {target}", "reason": "Fallback default scan due to AI error."}]

planner_agent = PlannerAgent()
