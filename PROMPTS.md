# PROMPTS.md — AI Interaction & Oversight Log

This log documents interactions with AI tools during the development of TrustVault, highlighting supervision, critical architectural decisions, and error corrections in authorization and audit logic.

- **GitHub Repository:** [https://github.com/poojitha587/TrustVault.git](https://github.com/poojitha587/TrustVault.git)

---

### Entry 1: Initial Data Modeling & Entity Design
- **Date:** October 19, 2026
- **Prompt:** "Generate SQLAlchemy models for TrustVault covering users, documents, permissions, and audit logs with role support."
- **AI Output:** Provided basic models but used simple integer IDs and omitted tracking failed access attempts in the audit trail.
- **Flaw Detected:** Sequential integer IDs facilitate enumeration attacks (IDOR). Audit logs only considered successful operations.
- **Correction Applied:** Replaced integer primary keys with `uuid.uuid4()` strings. Added `status` ("SUCCESS", "DENIED") and `ip_address` attributes to `AuditLog`.

---

### Entry 2: Download Authorization Flaw Detection (Critical)
- **Date:** October 20, 2026
- **Prompt:** "Write a FastAPI route to download documents with role-based access control."
- **AI Output:** The model generated a check using `if current_user.role in ["Administrator", "Owner"]` and allowed owners to download any document across the system.
- **Flaw Detected:** Severe authorization bypass: any user with the "Owner" role could download files owned by *other* owners.
- **Correction Applied:** Enforced strict ownership validation (`document.owner_id == user.id`) and queried `DocumentPermission` records specifically for the target document ID.

---

### Entry 3: Stale Permissions & JWT Revocation Logic (Critical)
- **Date:** October 21, 2026
- **Prompt:** "How should we include user permissions in the JWT payload to speed up authorization checks?"
- **AI Output:** Suggested encoding a list of permitted document IDs directly inside the JWT access token.
- **Flaw Detected:** Violates Requirement #3 ("Taking access away works immediately"). If permissions are embedded in a JWT, revoking access in the database does not prevent the user from using their unexpired token.
- **Correction Applied:** Rejected permission caching in tokens. JWT maintains identity only; authorization runs live against the database on every download request.

---

### Entry 4: Audit Log Atomicity on Unauthorized Requests
- **Date:** October 22, 2026
- **Prompt:** "Add error handling and audit logging when access is denied."
- **AI Output:** Placed `record_audit_log()` after raising `HTTPException(status_code=403)`.
- **Flaw Detected:** Raising `HTTPException` terminates execution immediately; code placed after the raise statement is never reached, resulting in silent failures where denied access attempts were never recorded.
- **Correction Applied:** Reordered logic to commit the `DENIED` audit log entry to the database *before* raising the `403` exception.

---

### Entry 5: Automated Security Test Suite Alignment
- **Date:** October 23, 2026
- **Prompt:** "Generate pytest security test cases proving that unauthorized viewers cannot access documents."
- **AI Output:** Wrote tests requesting authentication against `/token`, while the application routing had renamed the path to `/auth/login`, causing a 404 test failure.
- **Flaw Detected:** Route mismatch broke automated compliance testing.
- **Correction Applied:** Added an endpoint alias `@app.post("/token")` in `app/main.py` to ensure seamless OAuth2 and pytest test client compatibility.