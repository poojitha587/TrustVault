from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from app.models import DocumentPermission, AuditLog, Document

# Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT security configurations
SECRET_KEY = "trustvault-super-secure-secret-key-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

def authorize_document_access(db: Session, user, document: Document, action: str = "READ") -> bool:
    # 1. Administrators and Document Owners always have full access
    if user.role == "Administrator" or document.owner_id == user.id:
        return True
    
    # 2. Strict Server-Side Live DB Permission Check for Viewers/Others
    permission = db.query(DocumentPermission).filter(
        DocumentPermission.document_id == document.id,
        DocumentPermission.user_id == user.id
    ).first()

    if permission and permission.permission in [action, "EDIT"]:
        return True
    
    return False

def record_audit_log(db: Session, user_id: Optional[str], action: str, document_id: Optional[str], status: str, ip_address: Optional[str] = None):
    log_entry = AuditLog(
        user_id=user_id,
        action=action,
        document_id=document_id,
        status=status,
        ip_address=ip_address,
        timestamp=datetime.utcnow()
    )
    db.add(log_entry)
    db.commit()