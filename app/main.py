import os
import shutil
import uuid
from datetime import datetime
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import Base, engine, get_db
from app.models import User, Document, DocumentPermission, AuditLog
from app.security import (
    verify_password,
    get_password_hash,
    create_access_token,
    decode_access_token,
    authorize_document_access,
    record_audit_log,
)

# ---------------- Embedded Schemas (No external schemas.py needed) ----------------
class Token(BaseModel):
    access_token: str
    token_type: str
    role: str

class UserResponse(BaseModel):
    id: str
    email: str
    role: str

    class Config:
        from_attributes = True

class DocumentResponse(BaseModel):
    id: str
    original_filename: str
    owner_id: str
    uploaded_at: datetime

    class Config:
        from_attributes = True

class AuditLogResponse(BaseModel):
    id: str
    timestamp: datetime
    user_id: Optional[str] = None
    document_id: Optional[str] = None
    action: str
    status: str
    ip_address: Optional[str] = None

    class Config:
        from_attributes = True


# Initialize database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="TrustVault API",
    description="Secure document sharing platform with strict server-side authorization and audit trail.",
    version="1.0.0"
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
UPLOAD_DIR = "uploaded_files"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Mount static folder for frontend dashboard UI
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/", include_in_schema=False)
def serve_frontend():
    if os.path.exists("static/index.html"):
        return FileResponse("static/index.html")
    return {"message": "TrustVault API is running. Visit /docs for interactive documentation."}


# ---------------- Seed Initial Users ----------------
@app.on_event("startup")
def startup_event():
    db: Session = next(get_db())
    admin = db.query(User).filter(User.email == "admin@trustvault.com").first()
    if not admin:
        users = [
            User(id=str(uuid.uuid4()), email="admin@trustvault.com", hashed_password=get_password_hash("AdminPass123!"), role="Administrator"),
            User(id=str(uuid.uuid4()), email="owner@trustvault.com", hashed_password=get_password_hash("OwnerPass123!"), role="Owner"),
            User(id=str(uuid.uuid4()), email="viewer@trustvault.com", hashed_password=get_password_hash("ViewerPass123!"), role="Viewer"),
        ]
        db.add_all(users)
        db.commit()
    db.close()


# ---------------- Auth Dependency ----------------
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    payload = decode_access_token(token)
    if payload is None:
        raise credentials_exception
    user_id: str = payload.get("sub")
    if user_id is None:
        raise credentials_exception
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception
    return user


# ---------------- Endpoints ----------------
@app.post("/auth/login", response_model=Token, summary="Authenticate user")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.id, "email": user.email, "role": user.role})
    return {"access_token": access_token, "token_type": "bearer", "role": user.role}


@app.post("/documents/upload", summary="Upload a secure document")
def upload_document(
    request: Request,
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role not in ["Administrator", "Owner"]:
        record_audit_log(
            db,
            user_id=current_user.id,
            action="UNAUTHORIZED_ATTEMPT",
            document_id=None,
            status="DENIED",
            ip_address=request.client.host if request.client else None
        )
        raise HTTPException(status_code=403, detail="Viewer role is not allowed to upload documents.")

    doc_id = str(uuid.uuid4())
    stored_name = f"{doc_id}_{os.path.basename(file.filename)}"
    file_path = os.path.join(UPLOAD_DIR, stored_name)

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    new_doc = Document(
        id=doc_id,
        original_filename=file.filename,
        storage_path=file_path,
        owner_id=current_user.id,
        uploaded_at=datetime.utcnow()
    )
    db.add(new_doc)
    db.commit()

    record_audit_log(
        db,
        user_id=current_user.id,
        action="UPLOAD",
        document_id=doc_id,
        status="SUCCESS",
        ip_address=request.client.host if request.client else None
    )
    return {"message": "Document uploaded successfully", "id": doc_id, "filename": file.filename}


@app.get("/documents/", summary="List documents")
def list_documents(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    docs = db.query(Document).all()
    result = []
    for d in docs:
        result.append({
            "id": d.id,
            "filename": d.original_filename,
            "owner_id": d.owner_id,
            "created_at": d.uploaded_at.isoformat() if d.uploaded_at else ""
        })
    return result


@app.get("/documents/{document_id}/download", summary="Download file with live DB authorization")
def download_document(
    document_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    doc = db.query(Document).filter(Document.id == document_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    is_authorized = authorize_document_access(db, user=current_user, document=doc, action="READ")
    if not is_authorized:
        record_audit_log(
            db,
            user_id=current_user.id,
            action="DOWNLOAD",
            document_id=document_id,
            status="DENIED",
            ip_address=request.client.host if request.client else None
        )
        raise HTTPException(status_code=403, detail="Forbidden: You lack read permission for this file.")

    if not os.path.exists(doc.storage_path):
        raise HTTPException(status_code=404, detail="File content missing on server storage.")

    record_audit_log(
        db,
        user_id=current_user.id,
        action="DOWNLOAD",
        document_id=document_id,
        status="SUCCESS",
        ip_address=request.client.host if request.client else None
    )
    return FileResponse(path=doc.storage_path, filename=doc.original_filename, media_type="application/octet-stream")


@app.get("/audit/", summary="Fetch immutable audit trail")
def get_audit_trail(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).all()
    result = []
    for log in logs:
        result.append({
            "id": log.id,
            "timestamp": log.timestamp.isoformat() if log.timestamp else "",
            "actor_id": log.user_id or "Unknown",
            "action": log.action,
            "document_id": log.document_id or "-",
            "outcome": log.status
        })
    return result