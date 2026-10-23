# THREATS.md — TrustVault Security Model & Threat Assessment

This document outlines the threat modeling, defensive controls, and intentionally accepted risks for TrustVault as required by the Snovasys Hiring Challenge 2026.

- **GitHub Repository:** [https://github.com/poojitha587/TrustVault.git](https://github.com/poojitha587/TrustVault.git)
- **Live Deployment:** [https://trustvault-4bgd.onrender.com](https://trustvault-4bgd.onrender.com)

---

## 1. Threats Identified and Mitigated

### Threat 1: Insecure Direct Object References (IDOR) on File Downloads
- **Threat:** An authenticated malicious user or Viewer alters the `document_id` path parameter (e.g., `/documents/{doc_id}/download`) to fetch confidential files belonging to other owners.
- **Mitigation:** The download endpoint calls `authorize_document_access(db, user, document)` on the backend. This performs a live database lookup against `document_permissions` and document ownership before any file stream begins.
- **Test Verification:** Covered in `tests/test_security.py` where a Viewer requesting an unassigned file receives `403 Forbidden`.

### Threat 2: Stale Authorization via JWT Token Claims
- **Threat:** Embedding document permissions inside the client's JWT access token means an access revocation would remain ineffective until the token expires (up to 60 minutes).
- **Mitigation:** JWT tokens only encode user identity (`sub`, `email`, `role`). Authorization decisions query the live database state synchronously on every request. Revoking a database permission takes effect immediately.

### Threat 3: Direct Static File Path Traversal
- **Threat:** Attackers guessing direct storage URLs or manipulating filenames to download internal files outside the storage sandbox.
- **Mitigation:** Files are saved using generated UUID prefixes on the server filesystem. The raw upload folder is not served statically; file transfer is only routed through FastAPI's `FileResponse` following database authorization checks.

### Threat 4: Audit Trail Repudiation & Tampering
- **Threat:** A rogue user or compromised account attempts to modify or delete logs to hide unauthorized access attempts.
- **Mitigation:** Audit records (`audit_logs` table) have no update or delete endpoints exposed in the API. Failed authorization attempts (`status="DENIED"`) are committed synchronously prior to returning HTTP 403 responses.

---

## 2. Knowingly Accepted Risks & Future Enhancements

### Accepted Risk 1: SQLite Database Concurrency in Local Environment
- **Reason:** For rapid local testing and single-container Render deployment, SQLite is utilized by default. Under massive concurrent write spikes, SQLite table-locking can introduce latency.
- **Production Fix:** Transitioning to managed PostgreSQL with connection pooling.

### Accepted Risk 2: Server-Side At-Rest File Encryption
- **Reason:** Files are stored in an isolated filesystem directory with randomized UUID prefixes rather than being encrypted via AES-256 at rest.
- **Accepted Tradeoff:** Focus was placed on strict application-layer authorization and access control logic. In production, filesystem-level encryption (AWS KMS / LUKS) would protect raw disk access.