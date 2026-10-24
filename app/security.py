import os
from datetime import datetime, timedelta
from typing import Optional
import bcrypt
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.models import User, Document, DocumentPermission, AuditLog

SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-trustvault-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60


def verify_password(plain_password: str, hashed_password: str) -> bool:
    # Truncate plain_password to 72 bytes to satisfy bcrypt limits
    pwd_bytes = plain_password.encode("utf-8")[:72]
    hash_bytes = hashed_password.encode("utf-8")
    return bcrypt.checkpw(pwd_bytes, hash_bytes)


def get_password_hash(password: str) -> str:
    # Truncate password to 72 bytes to satisfy bcrypt limits
    pwd_bytes = password.encode("utf-8")[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


def authorize_document_access(db: Session, user: User, document: Document, action: str = "READ") -> bool:
    if user.role == "Administrator":
        return True
    if document.owner_id == user.id:
        return True
    permission = (
        db.query(DocumentPermission)
        .filter(
            DocumentPermission.document_id == document.id,
            DocumentPermission.user_id == user.id,
            DocumentPermission.permission == action,
        )
        .first()
    )
    return permission is not None


def record_audit_log(
    db: Session,
    user_id: Optional[str],
    action: str,
    document_id: Optional[str] = None,
    status: str = "SUCCESS",
    ip_address: Optional[str] = None,
):
    log_entry = AuditLog(
        user_id=user_id,
        action=action,
        document_id=document_id,
        status=status,
        ip_address=ip_address,
        timestamp=datetime.utcnow(),
    )
    db.add(log_entry)
    db.commit()