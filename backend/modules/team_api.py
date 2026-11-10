"""Named credentials in a shared operator workspace."""
import secrets
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from pydantic import Field, field_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from database import OperatorCredential, get_db
from modules.api_auth import verify_operator_key, _digest
from modules.scenarios import StrictModel

router = APIRouter(dependencies=[Depends(verify_operator_key)])


def public(row):
    return {key: getattr(row, key) for key in ('id', 'name', 'role', 'active', 'created_at')}


@router.get('/team/me')
def me(db: Session = Depends(get_db)):
    return db.info['principal']


@router.get('/team/credentials')
def credentials(db: Session = Depends(get_db)):
    return {'items': [public(row) for row in db.query(OperatorCredential).order_by(OperatorCredential.id).all()]}


class NewCredential(StrictModel):
    name: str = Field(min_length=1, max_length=80, pattern=r'^[A-Za-z0-9][A-Za-z0-9_. -]*$')
    role: Literal['viewer', 'operator', 'admin']

    @field_validator('name')
    @classmethod
    def strip_name(cls, value):
        value = value.strip()
        if value.lower() in {'bootstrap', 'system', 'operator'}:
            raise ValueError('Choose a personal name; this name is reserved for framework records')
        return value


@router.post('/team/credentials')
def create(payload: NewCredential, db: Session = Depends(get_db)):
    if db.query(OperatorCredential).count() >= 100:
        raise HTTPException(422, 'A workspace supports at most 100 named credentials')
    plaintext = secrets.token_urlsafe(32)
    row = OperatorCredential(name=payload.name, role=payload.role, key_hash=_digest(plaintext))
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, 'This credential name already exists; use a distinct name')
    return JSONResponse(content=jsonable_encoder({**public(row), 'key': plaintext}), headers={'Cache-Control': 'no-store'})


@router.delete('/team/credentials/{credential_id}')
def revoke(credential_id: int, db: Session = Depends(get_db)):
    row = db.get(OperatorCredential, credential_id)
    if row is None:
        raise HTTPException(404, 'Credential not found')
    if row.name == db.info['principal']['name']:
        raise HTTPException(409, 'Use another administrator credential to revoke your own')
    row.active = False
    db.commit()
    return public(row)
