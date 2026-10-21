from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
import jwt

from .database import get_db
from .models import User, Document, DocumentPermission, AuditLog
from .auth import SECRET_KEY, ALGORITHM

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

def authorize_document_access(
    document_id: str,
    required_permission: str,
    request: Request,
    user: User,
    db: Session
):
    doc = db.query(Document).filter(Document.id == document_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    # If owner, full access granted
    if doc.owner_id == user.id:
        return doc

    # Check live permissions in database (Guarantees instant revocation)
    perm = db.query(DocumentPermission).filter(
        DocumentPermission.document_id == document_id,
        DocumentPermission.user_id == user.id
    ).first()

    has_access = False
    if perm:
        if required_permission == "READ":
            has_access = True
        elif required_permission == "EDIT" and perm.permission == "EDIT":
            has_access = True

    if not has_access:
        # Non-negotiable: Log unauthorized attempt in AuditLog
        audit = AuditLog(
            user_id=user.id,
            document_id=document_id,
            action="UNAUTHORIZED_ATTEMPT",
            status="DENIED",
            ip_address=request.client.host if request.client else "unknown"
        )
        db.add(audit)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: You do not have permission to access this document."
        )

    return doc