import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from modules.planner import planner_agent

try:
    print("Testing planner...")
    plan = planner_agent.generate_plan('127.0.0.1', 'test')
    print("Plan:", plan)
except Exception as e:
    print("Exception:", e)
