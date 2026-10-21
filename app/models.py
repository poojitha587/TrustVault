import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, ForeignKey
from .database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="Viewer")  # Administrator, Owner, Viewer

class Document(Base):
    __tablename__ = "documents"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    original_filename = Column(String, nullable=False)
    storage_path = Column(String, nullable=False)  # Saved using internal UUID on disk
    category = Column(String, default="General")
    owner_id = Column(String, ForeignKey("users.id"), nullable=False)
    uploaded_at = Column(DateTime, default=datetime.utcnow)

class DocumentPermission(Base):
    __tablename__ = "document_permissions"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    document_id = Column(String, ForeignKey("documents.id"), nullable=False)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    permission = Column(String, nullable=False)  # READ, EDIT
    granted_at = Column(DateTime, default=datetime.utcnow)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, default=datetime.utcnow)
    user_id = Column(String, nullable=True)
    document_id = Column(String, nullable=True)
    action = Column(String, nullable=False)  # UPLOAD, DOWNLOAD, PERMISSION_REVOKE, UNAUTHORIZED_ATTEMPT
    status = Column(String, nullable=False)  # SUCCESS, DENIED
    ip_address = Column(String, nullable=True)