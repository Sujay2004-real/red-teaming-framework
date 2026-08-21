import os
from datetime import datetime
from urllib.parse import quote
from fastapi import Depends, FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from pathlib import Path

from database import AppSettings, Assessment, Finding, Target, ToolExecution, get_db
from models import AssessmentCreate, ExecuteRequest, PlanUpdate, SettingsUpdate, TargetCreate
from modules.analyzer import analyzer_agent
from modules.executor import executor
from modules.planner import planner_agent
from modules.policy_engine import policy_engine
from modules.reporter import reporter

app = FastAPI(title='Red Teaming Framework API', version='2.0')
app.add_middleware(CORSMiddleware, allow_origins=['http://localhost:5173'], allow_credentials=True, allow_methods=['*'], allow_headers=['*'])

def serialize_target(row):
    return {'id': row.id, 'name': row.name, 'scope_domain_ip': row.scope_domain_ip, 'authorized_scopes': row.authorized_scopes or [row.scope_domain_ip], 'created_at': row.created_at}

def serialize_assessment(row):
    return {'id': row.id, 'target_id': row.target_id, 'objective': row.objective, 'status': row.status, 'plan': row.plan or [], 'approval_required': row.approval_required, 'created_at': row.created_at, 'completed_at': row.completed_at}

def get_settings_row(db):
    row = db.query(AppSettings).filter(AppSettings.id == 1).first()
    if not row:
        row = AppSettings(id=1, gemini_api_key=os.getenv('GEMINI_API_KEY', ''), api_base_url=os.getenv('API_BASE_URL', 'https://api.openai.com/v1'), model_name=os.getenv('MODEL_NAME', 'gpt-4o-mini'))
        db.add(row); db.commit(); db.refresh(row)
    return row

def proxy_environment(settings):
    if not settings.proxy_url:
        return {}
    url = settings.proxy_url
    if settings.proxy_username and settings.proxy_password and '://' in url:
        scheme, remainder = url.split('://', 1)
        url = f'{scheme}://{quote(settings.proxy_username)}:{quote(settings.proxy_password)}@{remainder}'
    return {'HTTP_PROXY': url, 'HTTPS_PROXY': url, 'http_proxy': url, 'https_proxy': url}

@app.get('/capabilities')
def get_capabilities(): return policy_engine.public_capabilities()

@app.post('/requirements/extract')
async def extract_requirements(file: UploadFile = File(...)):
    allowed = {'.txt', '.md', '.pdf', '.docx'}
    suffix = Path(file.filename or '').suffix.lower()
    if suffix not in allowed: raise HTTPException(415, 'Supported requirement files: .txt, .md, .pdf, .docx')
    content = await file.read()
    if len(content) > 5 * 1024 * 1024: raise HTTPException(413, 'Requirement file must be 5 MB or smaller')
    try:
        if suffix in {'.txt', '.md'}: text = content.decode('utf-8', errors='ignore')
        elif suffix == '.pdf':
            from pypdf import PdfReader
            import io
            text = '\\n'.join(page.extract_text() or '' for page in PdfReader(io.BytesIO(content)).pages)
        else:
            from docx import Document
            import io
            doc = Document(io.BytesIO(content))
            text = '\\n'.join(p.text for p in doc.paragraphs)
    except Exception as exc: raise HTTPException(422, f'Could not read requirement file: {exc}')
    text = text.strip()
    if not text: raise HTTPException(422, 'Requirement file contains no readable text')
    return {'filename': file.filename, 'text': text[:30000]}

@app.get('/health')
def health(): return {'status': 'ok'}

@app.get('/settings')
def get_settings(db: Session = Depends(get_db)):
    row = get_settings_row(db)
    return {'gemini_configured': bool(row.gemini_api_key), 'api_base_url': row.api_base_url or '', 'model_name': row.model_name or '', 'proxy_url': row.proxy_url or '', 'proxy_configured': bool(row.proxy_url), 'proxy_username': row.proxy_username or ''}

@app.put('/settings')
def update_settings(payload: SettingsUpdate, db: Session = Depends(get_db)):
    row = get_settings_row(db)
    values = payload.model_dump(exclude_unset=True)
    for key, value in values.items():
        if value is not None and (value != '' or key in ('proxy_url', 'proxy_username')):
            setattr(row, key, value)
    db.commit()
    return get_settings(db)

@app.post('/targets/')
def create_target(payload: TargetCreate, db: Session = Depends(get_db)):
    scopes = payload.authorized_scopes or [payload.scope_domain_ip]
    row = Target(name=payload.name, scope_domain_ip=payload.scope_domain_ip, authorized_scopes=scopes)
    db.add(row); db.commit(); db.refresh(row)
    return serialize_target(row)

@app.get('/targets/')
def get_targets(db: Session = Depends(get_db)): return [serialize_target(row) for row in db.query(Target).all()]

@app.post('/assessments/')
def create_assessment(payload: AssessmentCreate, db: Session = Depends(get_db)):
    target = db.query(Target).filter(Target.id == payload.target_id).first()
    if not target: raise HTTPException(404, 'Target not found')
    settings = get_settings_row(db)
    plan = payload.plan
    requirement_context = (payload.requirements or '').strip()
    if not plan:
        plan, source = planner_agent.generate_plan(target.scope_domain_ip, payload.objective, settings.gemini_api_key, settings.api_base_url, settings.model_name, requirement_context, policy_engine)
    else: source = 'user'
    for step in plan:
        step.setdefault('enabled', True); step.setdefault('reason', 'User-defined assessment command.')
    row = Assessment(target_id=payload.target_id, objective=payload.objective, plan=plan, status='awaiting_approval')
    db.add(row); db.commit(); db.refresh(row)
    result = serialize_assessment(row); result['plan_source'] = source
    return result

@app.get('/assessments/')
def get_assessments(db: Session = Depends(get_db)): return [serialize_assessment(row) for row in db.query(Assessment).order_by(Assessment.id.desc()).all()]

@app.get('/assessments/{assessment_id}')
def get_assessment(assessment_id: int, db: Session = Depends(get_db)):
    row = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not row: raise HTTPException(404, 'Assessment not found')
    executions = db.query(ToolExecution).filter(ToolExecution.assessment_id == assessment_id).all()
    findings = db.query(Finding).filter(Finding.assessment_id == assessment_id).order_by(Finding.priority_score.desc()).all()
    result = serialize_assessment(row)
    result['executions'] = [{'id': e.id, 'step_index': e.step_index, 'tool_name': e.tool_name, 'command': e.command, 'stdout': e.stdout, 'stderr': e.stderr, 'return_code': e.return_code, 'duration_ms': e.duration_ms, 'approved_by_user': e.approved_by_user, 'executed_at': e.executed_at} for e in executions]
    result['findings'] = [{'id': f.id, 'title': f.title, 'description': f.description, 'severity': f.severity, 'evidence': f.evidence, 'remediation': f.remediation, 'risk_score': f.risk_score, 'priority_score': f.priority_score, 'confidence_score': f.confidence_score, 'source_tools': f.source_tools} for f in findings]
    return result

@app.put('/assessments/{assessment_id}/plan')
def update_plan(assessment_id: int, payload: PlanUpdate, db: Session = Depends(get_db)):
    row = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not row: raise HTTPException(404, 'Assessment not found')
    if db.query(ToolExecution).filter(ToolExecution.assessment_id == assessment_id).first(): raise HTTPException(409, 'Plan cannot be edited after execution begins')
    for step in payload.plan:
        if not step.get('tool') or not step.get('command'): raise HTTPException(422, 'Every plan step needs a tool and command')
        step.setdefault('enabled', True); step.setdefault('reason', 'User-defined assessment command.')
    row.plan = payload.plan; row.status = 'awaiting_approval'; db.commit()
    return serialize_assessment(row)

@app.post('/assessments/{assessment_id}/execute')
async def execute_step(assessment_id: int, payload: ExecuteRequest, db: Session = Depends(get_db)):
    row = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not row: raise HTTPException(404, 'Assessment not found')
    if not payload.approved: raise HTTPException(403, 'Explicit human approval is required')
    if payload.step_index >= len(row.plan or []): raise HTTPException(400, 'Invalid step index')
    step = row.plan[payload.step_index]
    if not step.get('enabled', True): raise HTTPException(400, 'This step is disabled')
    target = db.query(Target).filter(Target.id == row.target_id).first()
    valid, reason, capability = policy_engine.validate_command(step['command'], target.authorized_scopes or [target.scope_domain_ip])
    if not valid: raise HTTPException(403, reason)
    settings = get_settings_row(db)
    row.status = 'running'; db.commit()
    result = await executor.execute_command(step['tool'], step['command'], proxy_environment(settings))
    execution = ToolExecution(assessment_id=row.id, step_index=payload.step_index, tool_name=step['tool'], command=step['command'], stdout=result['stdout'], stderr=result['stderr'], return_code=result['return_code'], duration_ms=result['duration_ms'], approved_by_user=True)
    db.add(execution)
    enabled = [i for i, item in enumerate(row.plan) if item.get('enabled', True)]
    executed = {e.step_index for e in db.query(ToolExecution).filter(ToolExecution.assessment_id == row.id).all()} | {payload.step_index}
    if all(index in executed for index in enabled): row.status = 'ready_for_analysis'
    db.commit()
    return {'message': 'Execution finished', 'policy': reason, 'capability': capability, 'result': result}

@app.post('/assessments/{assessment_id}/analyze')
def analyze_assessment(assessment_id: int, db: Session = Depends(get_db)):
    row = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not row: raise HTTPException(404, 'Assessment not found')
    executions = db.query(ToolExecution).filter(ToolExecution.assessment_id == assessment_id).all()
    if not executions: raise HTTPException(400, 'Execute at least one approved plan step first')
    raw = [{'tool': e.tool_name, 'stdout': e.stdout or '', 'stderr': e.stderr or ''} for e in executions]
    settings = get_settings_row(db)
    analyzed = analyzer_agent.analyze_results(raw, settings.gemini_api_key, settings.api_base_url, settings.model_name)
    db.query(Finding).filter(Finding.assessment_id == assessment_id).delete()
    for item in analyzed:
        db.add(Finding(assessment_id=assessment_id, fingerprint=item['fingerprint'], title=item.get('title','Unknown finding'), description=item.get('description',''), severity=item['severity'], evidence=item.get('evidence',''), remediation=item.get('remediation',''), risk_score=item['risk_score'], priority_score=item['priority_score'], confidence_score=item['confidence_score'], source_tools=item.get('source_tools',[])))
    row.status = 'analyzed'; row.completed_at = datetime.utcnow(); db.commit()
    return {'message': 'Analysis complete', 'findings_count': len(analyzed), 'analyzer': 'gemini' if settings.gemini_api_key else 'deterministic-fallback'}

@app.post('/assessments/{assessment_id}/report')
def generate_report(assessment_id: int, db: Session = Depends(get_db)):
    row = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not row: raise HTTPException(404, 'Assessment not found')
    target = db.query(Target).filter(Target.id == row.target_id).first()
    findings = db.query(Finding).filter(Finding.assessment_id == assessment_id).order_by(Finding.priority_score.desc()).all()
    executions = db.query(ToolExecution).filter(ToolExecution.assessment_id == assessment_id).all()
    os.makedirs('./data/reports', exist_ok=True)
    path = f'./data/reports/report_{assessment_id}.html'
    reporter.generate_html_report(target.scope_domain_ip, row.objective, [f.__dict__ for f in findings], [e.__dict__ for e in executions], path)
    row.status = 'reported'; db.commit()
    return {'message': 'Report generated', 'download_url': f'/reports/{assessment_id}'}

@app.get('/reports/{assessment_id}')
def download_report(assessment_id: int):
    path = f'./data/reports/report_{assessment_id}.html'
    if not os.path.exists(path): raise HTTPException(404, 'Report not generated')
    return FileResponse(path, media_type='text/html', filename=f'security-assessment-{assessment_id}.html')
