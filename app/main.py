from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form, Request
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
import os
import shutil
import uuid

from .database import engine, Base, get_db
from .models import User, Document, DocumentPermission, AuditLog
from .auth import get_password_hash, verify_password, create_access_token
from .security import get_current_user, authorize_document_access

# Create tables automatically
Base.metadata.create_all(bind=engine)

app = FastAPI(title="TrustVault API", version="1.0.0")

UPLOAD_DIR = "storage"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# 1. Seed Initial Data (Admin, Owner, Viewer)
@app.on_event("startup")
def seed_data():
    db = next(get_db())
    if not db.query(User).filter(User.email == "admin@trustvault.com").first():
        admin = User(email="admin@trustvault.com", hashed_password=get_password_hash("AdminPass123!"), role="Administrator")
        owner = User(email="owner@trustvault.com", hashed_password=get_password_hash("OwnerPass123!"), role="Owner")
        viewer = User(email="viewer@trustvault.com", hashed_password=get_password_hash("ViewerPass123!"), role="Viewer")
        db.add_all([admin, owner, viewer])
        db.commit()

# 2. Authentication Login Endpoint
@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    
    access_token = create_access_token(data={"sub": user.email, "role": user.role})
    return {"access_token": access_token, "token_type": "bearer"}

# 3. Document Upload Endpoint (Owner Only)
@app.post("/documents/upload")
def upload_document(
    file: UploadFile = File(...),
    category: str = Form("General"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    if user.role not in ["Owner", "Administrator"]:
        raise HTTPException(status_code=403, detail="Only Owners or Administrators can upload documents.")

    # Save file securely using internal UUID to prevent path traversal
    file_extension = os.path.splitext(file.filename)[1]
    storage_filename = f"{uuid.uuid4()}{file_extension}"
    storage_path = os.path.join(UPLOAD_DIR, storage_filename)

    with open(storage_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    doc = Document(
        original_filename=file.filename,
        storage_path=storage_path,
        category=category,
        owner_id=user.id
    )
    db.add(doc)
    db.commit()
    db.refresh(doc)

    # Log action
    audit = AuditLog(user_id=user.id, document_id=doc.id, action="UPLOAD", status="SUCCESS")
    db.add(audit)
    db.commit()

    return {"message": "Document uploaded successfully", "document_id": doc.id}

# 4. Secure Document Download / View Endpoint (Rule #1 Enforced)
@app.get("/documents/{document_id}/download")
def download_document(
    document_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    # Server-side authorization check (Guarantees Rule #1)
    doc = authorize_document_access(document_id, "READ", request, user, db)

    # Log successful access
    audit = AuditLog(user_id=user.id, document_id=doc.id, action="DOWNLOAD", status="SUCCESS")
    db.add(audit)
    db.commit()

    return FileResponse(doc.storage_path, filename=doc.original_filename)

# 5. Admin Audit Logs View
@app.get("/admin/audit-logs")
def view_audit_logs(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role != "Administrator":
        raise HTTPException(status_code=403, detail="Access denied. Admins only.")
    
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).all()
    return logs