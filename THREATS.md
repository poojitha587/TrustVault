# Threat Model & Security Architecture (TrustVault)

## 1. Threat: Insecure Direct Object Reference (IDOR) & Unauthorized Download
- **Risk:** A user guesses or captures a valid `document_id` and tries to download it without permission.
- **Mitigation:** Server-side authorization (`authorize_document_access` in `app/security.py`) checks the database live on every single request to verify if a valid permission grant exists between the user and the document. If absent, access is instantly denied with HTTP 403 and logged in `AuditLog`.

## 2. Threat: Revoked Permission Stale Cache
- **Risk:** An administrator or owner revokes a user's access, but a cached token or session still allows downloads.
- **Mitigation:** We do not rely on stateless JWT claims for document permissions. Every download queries the `document_permissions` table directly in real-time, ensuring instant revocation.

## 3. Threat: Path Traversal via Filename Upload
- **Risk:** Malicious filenames (e.g., `../../etc/passwd`) designed to overwrite system files during upload.
- **Mitigation:** Original filenames are stripped of raw paths, and files are stored on disk using unique generated UUIDs (`uuid.uuid4()`), mapping back safely via database records.

## 4. Threat: Tampering with Audit Trails
- **Risk:** Malicious actors deleting or altering logs to cover unauthorized access.
- **Mitigation:** Audit logs are append-only rows committed directly to the persistent database (`trustvault.db`) with timestamp, IP address, user ID, and action status (`SUCCESS` / `DENIED`).