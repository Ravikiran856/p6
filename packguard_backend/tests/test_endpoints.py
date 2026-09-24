"""Integration tests for core REST endpoints."""

from __future__ import annotations


def test_health(client):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert "modelVersion" in body


def test_signup_and_login(client):
    token = {"idToken": "dev:new-user:new@example.com"}
    signup = client.post("/api/v1/auth/signup", json=token)
    assert signup.status_code == 201
    assert signup.json()["isNewUser"] is True

    login = client.post("/api/v1/auth/login", json=token)
    assert login.status_code == 200
    assert login.json()["uid"] == "new-user"


def test_scan_package_requires_auth(client):
    response = client.post("/api/v1/scan/package", json={"packageName": "six"})
    assert response.status_code == 401


def test_scan_package_and_history(client, auth_headers):
    scan = client.post(
        "/api/v1/scan/package",
        json={"packageName": "six"},
        headers=auth_headers,
    )
    assert scan.status_code == 200
    body = scan.json()
    assert body["packageName"] == "six"
    assert 0 <= body["riskScore"] <= 100
    assert body["riskLabel"] in ("safe", "suspicious", "high_risk")
    assert isinstance(body["explanation"], list)
    assert "findings" in body
    assert isinstance(body["findings"], list)
    scan_id = body["scanId"]

    history = client.get("/api/v1/scan/history", headers=auth_headers)
    assert history.status_code == 200
    items = history.json()["items"]
    assert any(item["scanId"] == scan_id for item in items)

    pdf = client.get(f"/api/v1/scan/report/{scan_id}/pdf", headers=auth_headers)
    assert pdf.status_code == 200
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.content[:4] == b"%PDF"


def test_parse_requirements_invalid(client, auth_headers):
    files = {"requirements_file": ("requirements.txt", b"# empty\n", "text/plain")}
    response = client.post("/api/v1/scan/package", files=files, headers=auth_headers)
    assert response.status_code == 400


def test_rescan_check(client, auth_headers):
    response = client.post(
        "/api/v1/scan/rescan-check?run_sync=true",
        headers=auth_headers,
    )
    assert response.status_code == 202
    assert "jobStatus" in response.json()
