from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Dict, Any

from database import get_db, Target, Assessment, ToolExecution, Finding
from models import TargetCreate, Target as TargetSchema, AssessmentCreate, Assessment as AssessmentSchema
from modules.policy_engine import policy_engine
from modules.planner import planner_agent
from modules.executor import executor
from modules.analyzer import analyzer_agent
from modules.reporter import reporter

import os

app = FastAPI(title="Red Teaming Framework API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/targets/", response_model=TargetSchema)
def create_target(target: TargetCreate, db: Session = Depends(get_db)):
    db_target = Target(**target.dict())
    db.add(db_target)
    db.commit()
    db.refresh(db_target)
    return db_target

@app.get("/targets/", response_model=List[TargetSchema])
def get_targets(db: Session = Depends(get_db)):
    return db.query(Target).all()

@app.post("/assessments/", response_model=AssessmentSchema)
def create_assessment(assessment: AssessmentCreate, db: Session = Depends(get_db)):
    target = db.query(Target).filter(Target.id == assessment.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    # Generate Plan
    plan = planner_agent.generate_plan(target.scope_domain_ip, assessment.objective)
    
    db_assessment = Assessment(**assessment.dict(), plan=plan)
    db.add(db_assessment)
    db.commit()
    db.refresh(db_assessment)
    return db_assessment

@app.get("/assessments/", response_model=List[AssessmentSchema])
def get_assessments(db: Session = Depends(get_db)):
    return db.query(Assessment).all()

class ExecuteRequest(BaseModel):
    step_index: int

@app.post("/assessments/{assessment_id}/execute")
async def execute_step(assessment_id: int, req: ExecuteRequest, db: Session = Depends(get_db)):
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    
    plan = assessment.plan
    if not plan or req.step_index >= len(plan):
        raise HTTPException(status_code=400, detail="Invalid step index")

    step = plan[req.step_index]
    command = step.get("command")
    tool = step.get("tool")

    if not policy_engine.validate_command(command):
        raise HTTPException(status_code=403, detail="Command blocked by policy engine")
    
    # Execute the command
    result = await executor.execute_command(tool, command)
    
    db_exec = ToolExecution(
        assessment_id=assessment.id,
        tool_name=tool,
        command=command,
        stdout=result["stdout"],
        stderr=result["stderr"],
        return_code=result["return_code"]
    )
    db.add(db_exec)
    db.commit()

    return {"message": "Execution finished", "result": result}

@app.post("/assessments/{assessment_id}/analyze")
def analyze_assessment(assessment_id: int, db: Session = Depends(get_db)):
    executions = db.query(ToolExecution).filter(ToolExecution.assessment_id == assessment_id).all()
    
    raw_outputs = []
    for exec in executions:
        raw_outputs.append({
            "tool": exec.tool_name,
            "stdout": exec.stdout
        })

    findings_json = analyzer_agent.analyze_results(raw_outputs)
    
    for f in findings_json:
        db_finding = Finding(
            assessment_id=assessment_id,
            title=f.get("title", "Unknown"),
            description=f.get("description", ""),
            severity=f.get("severity", "Low"),
            evidence=f.get("evidence", ""),
            remediation=f.get("remediation", "")
        )
        db.add(db_finding)
    
    db.commit()
    return {"message": "Analysis complete", "findings_count": len(findings_json)}

@app.post("/assessments/{assessment_id}/report")
def generate_report(assessment_id: int, db: Session = Depends(get_db)):
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    target = db.query(Target).filter(Target.id == assessment.target_id).first()
    findings = db.query(Finding).filter(Finding.assessment_id == assessment_id).all()
    
    findings_list = []
    for f in findings:
        findings_list.append({
            "title": f.title,
            "description": f.description,
            "severity": f.severity,
            "evidence": f.evidence,
            "remediation": f.remediation
        })

    os.makedirs("./data/reports", exist_ok=True)
    report_path = f"./data/reports/report_{assessment_id}.html"
    
    reporter.generate_html_report(target.scope_domain_ip, assessment.objective, findings_list, report_path)
    
    return {"message": "Report generated", "report_path": report_path}
