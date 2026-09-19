"""Paged workspace reads and remediation workflow, independent of execution."""
from datetime import date
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import or_
from sqlalchemy.orm import Session, defer
from database import Assessment, Finding, FindingReview, ReportVersion, ToolExecution, get_db, utcnow
from modules.api_auth import verify_operator_key

router = APIRouter(dependencies=[Depends(verify_operator_key)])


def require_assessment(db, assessment_id):
    row = db.get(Assessment, assessment_id)
    if not row:
        raise HTTPException(404, 'Assessment not found')
    return row


def review_data(row):
    return {k: getattr(row, k) for k in ('status', 'owner', 'due_date', 'justification', 'comments', 'retest_evidence', 'updated_at')} if row else {'status': 'open', 'owner': '', 'comments': []}


@router.get('/catalog/assessments')
def catalog(offset: int = Query(0, ge=0), limit: int = Query(30, ge=1, le=100), db: Session = Depends(get_db)):
    query = db.query(Assessment)
    rows = query.order_by(Assessment.id.desc()).offset(offset).limit(limit).all()
    fields = ('id', 'target_id', 'objective', 'status', 'current_phase', 'created_at', 'completed_at', 'plan_version')
    return {'items': [{k: getattr(row, k) for k in fields} for row in rows], 'total': query.count(), 'offset': offset, 'limit': limit}


@router.get('/assessments/{assessment_id}/snapshot')
def snapshot(assessment_id: int, db: Session = Depends(get_db)):
    from main import serialize_assessment, is_retryable, discovered_hosts_for
    row = require_assessment(db, assessment_id)
    result = serialize_assessment(row)
    executions = db.query(ToolExecution).filter_by(assessment_id=assessment_id).options(
        defer(ToolExecution.stdout), defer(ToolExecution.live_output)).order_by(ToolExecution.step_index).all()
    result['executions'] = [{k: getattr(e, k) for k in ('id', 'step_index', 'tool_name', 'command', 'return_code', 'state', 'attempt', 'duration_ms', 'executed_at', 'execution_host')}
                            | {'complete': e.return_code is not None, 'retryable': is_retryable(e)} for e in executions]
    result['finding_count'] = db.query(Finding).filter_by(assessment_id=assessment_id).count()
    result['findings'] = []
    # The network-inventory panel reads discovered_hosts off the same load path
    # the UI uses (this snapshot), so populate it here. stdout is deferred above
    # for weight, so pull just the nmap rows (few) with their output loaded.
    host_executions = db.query(ToolExecution).filter_by(assessment_id=assessment_id, tool_name='nmap').all()
    result['discovered_hosts'] = discovered_hosts_for(host_executions)
    return result


@router.get('/assessments/{assessment_id}/findings')
def findings(assessment_id: int, offset: int = Query(0, ge=0), limit: int = Query(30, ge=1, le=100),
             search: str = Query('', max_length=200), severity: str = '', verification: str = '',
             tool: str = '', db: Session = Depends(get_db)):
    require_assessment(db, assessment_id)
    query = db.query(Finding).filter_by(assessment_id=assessment_id)
    if search:
        query = query.filter(or_(Finding.title.contains(search, autoescape=True), Finding.endpoint.contains(search, autoescape=True)))
    if severity:
        query = query.filter(Finding.severity == severity)
    if verification:
        query = query.filter(Finding.verification == ('' if verification == 'unverified' else verification))
    if tool:
        query = query.filter(Finding.source_tools.contains('"' + tool + '"'))
    total = query.count()
    rows = query.options(defer(Finding.evidence), defer(Finding.exploit_evidence)).order_by(Finding.priority_score.desc(), Finding.id).offset(offset).limit(limit).all()
    reviews = {r.fingerprint: r for r in db.query(FindingReview).filter_by(assessment_id=assessment_id).filter(FindingReview.fingerprint.in_([r.fingerprint for r in rows])).all()}
    fields = ('id', 'fingerprint', 'title', 'severity', 'endpoint', 'parameter', 'priority_score', 'confidence_score', 'verification', 'source_tools', 'phase')
    return {'items': [{k: getattr(r, k) for k in fields} | {'review': review_data(reviews.get(r.fingerprint))} for r in rows], 'total': total, 'offset': offset, 'limit': limit}


@router.get('/assessments/{assessment_id}/findings/{finding_id}')
def finding_detail(assessment_id: int, finding_id: int, db: Session = Depends(get_db)):
    from main import serialize_finding
    row = db.query(Finding).filter_by(id=finding_id, assessment_id=assessment_id).first()
    if not row:
        raise HTTPException(404, 'Finding not found')
    review = db.query(FindingReview).filter_by(assessment_id=assessment_id, fingerprint=row.fingerprint).first()
    return serialize_finding(row) | {'review': review_data(review)}


class ReviewUpdate(BaseModel):
    status: Literal['open', 'in_progress', 'resolved', 'accepted_risk', 'reopened'] = 'open'
    owner: str = Field('', max_length=150)
    due_date: date | None = None
    justification: str = Field('', max_length=4000)
    comment: str = Field('', max_length=2000)
    retest_evidence: str = Field('', max_length=10000)


@router.put('/assessments/{assessment_id}/findings/{finding_id}/review')
def update_review(assessment_id: int, finding_id: int, payload: ReviewUpdate, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter_by(id=finding_id, assessment_id=assessment_id).first()
    if not finding:
        raise HTTPException(404, 'Finding not found')
    if payload.status == 'accepted_risk' and not payload.justification.strip():
        raise HTTPException(422, 'Accepted risk requires a justification')
    if payload.status == 'resolved' and not payload.retest_evidence.strip():
        raise HTTPException(422, 'Resolved findings require retest evidence')
    row = db.query(FindingReview).filter_by(assessment_id=assessment_id, fingerprint=finding.fingerprint).first()
    if not row:
        row = FindingReview(assessment_id=assessment_id, fingerprint=finding.fingerprint)
        db.add(row)
    for key in ('status', 'owner', 'justification', 'retest_evidence'):
        setattr(row, key, getattr(payload, key))
    row.due_date = payload.due_date.isoformat() if payload.due_date else ''
    if payload.comment.strip():
        comments = row.comments or []
        if len(comments) >= 100:
            raise HTTPException(422, 'This review has reached its 100-comment limit')
        row.comments = comments + [{'text': payload.comment.strip(), 'created_at': utcnow().isoformat()}]
    db.commit()
    return review_data(row)


@router.get('/assessments/{assessment_id}/compare/{baseline_id}')
def compare(assessment_id: int, baseline_id: int, db: Session = Depends(get_db)):
    current, baseline = require_assessment(db, assessment_id), require_assessment(db, baseline_id)
    if current.target_id != baseline.target_id or current.id == baseline.id:
        raise HTTPException(422, 'Compare two different assessments of the same target')
    if not current.analyzed_phases or not baseline.analyzed_phases:
        raise HTTPException(409, 'Analyze both assessments before comparison')
    if set(current.analyzed_phases) != set(baseline.analyzed_phases):
        raise HTTPException(409, 'Compare assessments with the same analyzed phases')
    before = {r.fingerprint: r for r in db.query(Finding).filter_by(assessment_id=baseline_id).all()}
    after = {r.fingerprint: r for r in db.query(Finding).filter_by(assessment_id=assessment_id).all()}
    resolved = {r.fingerprint for r in db.query(FindingReview).filter_by(assessment_id=baseline_id, status='resolved').all()}
    items = []
    for key in sorted(before.keys() | after.keys()):
        state = 'new' if key not in before else 'not_observed' if key not in after else 'reopened' if key in resolved else 'persistent'
        row = after.get(key) or before[key]
        items.append({'fingerprint': key, 'title': row.title, 'endpoint': row.endpoint, 'state': state})
    return {'items': items, 'note': 'Not observed means absent in this run; remediation requires retest evidence. Coverage and tool failures may differ.'}


@router.get('/assessments/{assessment_id}/executions/{execution_id}/evidence')
def execution_evidence(assessment_id: int, execution_id: int, db: Session = Depends(get_db)):
    from main import serialize_execution
    row = db.query(ToolExecution).filter_by(id=execution_id, assessment_id=assessment_id).first()
    if not row:
        raise HTTPException(404, 'Execution not found')
    return serialize_execution(row)


@router.get('/assessments/{assessment_id}/reports')
def report_versions(assessment_id: int, db: Session = Depends(get_db)):
    require_assessment(db, assessment_id)
    return [{k: getattr(r, k) for k in ('id', 'digest', 'provenance', 'created_at')} for r in db.query(ReportVersion).filter_by(assessment_id=assessment_id).order_by(ReportVersion.id.desc()).all()]


@router.get('/assessments/{assessment_id}/reports/{version_id}')
def report_version(assessment_id: int, version_id: int, db: Session = Depends(get_db)):
    row = db.query(ReportVersion).filter_by(id=version_id, assessment_id=assessment_id).first()
    if not row:
        raise HTTPException(404, 'Report version not found')
    from pathlib import Path
    if not Path(row.path).is_file():
        raise HTTPException(404, 'Report file is unavailable')
    return FileResponse(row.path, media_type='text/html', filename=f'assessment-{assessment_id}-v{version_id}.html')
