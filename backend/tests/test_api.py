import os
import pytest
from fastapi.testclient import TestClient

# Must set these before importing main
os.environ["JWT_SECRET"] = "test_secret_key_123"
os.environ["ADMIN_SECURE_PIN"] = "TEST_PIN_123"

from main import app
from database import engine
import models

models.Base.metadata.create_all(bind=engine)

client = TestClient(app)

def test_unauthenticated_endpoints():
    res = client.post("/api/vision-scan", json={"url": "http://test.com", "screenshot_base64": "dummy"})
    assert res.status_code == 401

    res = client.get("/api/node-investigate?domain=google.com")
    assert res.status_code == 401

    res = client.get("/api/speedtest/ping")
    assert res.status_code == 401

def test_auth_flow():
    # Register
    res = client.post("/api/auth/register", json={
        "username": "testuser",
        "password": "testpassword",
        "role": "User"
    })
    assert res.status_code in [200, 400] # Allow 400 if already exists from previous test

    # Login
    res = client.post("/api/auth/token", data={
        "username": "testuser",
        "password": "testpassword"
    })
    assert res.status_code == 200
    token = res.json()["access_token"]
    
    # Use token
    res = client.get("/api/speedtest/ping", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200

def test_admin_rbac():
    res = client.post("/api/auth/register", json={
        "username": "testadmin",
        "password": "testpassword",
        "role": "Admin",
        "admin_pin": "WRONG_PIN"
    })
    assert res.status_code == 403

def test_detect_url():
    payload = {
        "url": "https://google.com",
        "url_length": 18,
        "has_at_symbol": False,
        "num_subdomains": 0,
        "is_https": True,
        "num_redirects": 0,
        "suspicious_dom_elements": 0
    }
    res = client.post("/api/detect", json=payload)
    assert res.status_code == 200
    assert res.json()["status"] == "Safe"
