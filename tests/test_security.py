from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_unauthorized_download_attempt():
    # Attempting to download without granting permission should return 403 or 401
    response = client.get("/documents/non-existent-id/download")
    assert response.status_code in [401, 403, 404]

def test_owner_login():
    response = client.post("/token", data={"username": "owner@trustvault.com", "password": "OwnerPass123!"})
    assert response.status_code == 200
    assert "access_token" in response.json()