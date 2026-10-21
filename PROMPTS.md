# Prompts & AI Usage Log (TrustVault)

## Entry 1: Database Schema Design & SQLAlchemy Models
- **Date:** October 19, 2026
- **Prompt:** "Write SQLAlchemy models for a secure document vault app in FastAPI including User, Document, DocumentPermission, and AuditLog with UUID primary keys and foreign key constraints."
- **What it produced:** Generated standard SQLAlchemy ORM models with proper relationships and foreign keys.
- **What was wrong with it:** It used standard auto-incrementing integer IDs which are vulnerable to enumeration attacks (IDOR).
- **What I did instead:** Modified the models to use UUIDs (`uuid.uuid4()`) for all primary keys to prevent sequential ID guessing.

## Entry 2: Authorization Middleware & Real-Time Permission Checks (Critical)
- **Date:** October 20, 2026
- **Prompt:** "Write a FastAPI dependency function that checks if a user has read or edit permission on a document before allowing download."
- **What it produced:** An initial function that checked role claims directly from the decoded JWT token payload.
- **What was wrong with it:** Relying on JWT claims for permissions fails Rule #3 of the challenge—if an admin revokes access, the existing token would still let the user download the file until it expired.
- **What I did instead:** Completely rewrote `authorize_document_access` in `app/security.py` to query the live `document_permissions` table on every single request, guaranteeing instant permission revocation.

## Entry 3: Audit Logging for Unauthorized Attempts
- **Date:** October 20, 2026
- **Prompt:** "How should I log unauthorized file download attempts in FastAPI and SQLAlchemy?"
- **What it produced:** Suggested printing to console or writing to an external text log file.
- **What was wrong with it:** Text log files can be easily tampered with or deleted, violating the evidence requirement of the audit trail.
- **What I did instead:** Created a persistent `AuditLog` database model that records user_id, document_id, action (`UNAUTHORIZED_ATTEMPT`), status (`DENIED`), and IP address directly into `trustvault.db`.

## Entry 4: Secure File Upload and Path Traversal Prevention
- **Date:** October 21, 2026
- **Prompt:** "Write a FastAPI endpoint to handle file uploads and save them in a local storage directory."
- **What it produced:** Used `file.filename` directly to save the uploaded file on disk.
- **What was wrong with it:** Direct use of user-supplied filenames allows path traversal attacks (e.g., `../../etc/passwd` or overwriting critical system files).
- **What I did instead:** Stripped raw paths and saved files to disk using unique generated UUIDs (`uuid.uuid4()`), keeping the original filename safely stored only as metadata in the database.

## Entry 5: Automated Security Testing with Pytest
- **Date:** October 21, 2026
- **Prompt:** "Write automated pytest test cases for FastAPI to verify that unauthorized users receive a 403 Forbidden response when trying to download documents."
- **What it produced:** Basic test cases checking for general HTTP exceptions.
- **What was wrong with it:** The tests didn't simulate missing or invalid authorization tokens correctly against protected endpoints.
- **What I did instead:** Configured `TestClient` in `tests/test_security.py` to explicitly test both unauthenticated requests (401) and unauthorized cross-user download attempts (403).