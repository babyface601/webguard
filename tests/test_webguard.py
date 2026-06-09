"""
Tests unitaires — WebGuard
Lance avec : pytest tests/
"""
import sys
import os
import json
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import app as app_module
from app import app, init_db

# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def client(tmp_path):
    """Client de test Flask avec base SQLite et dossier reports temporaires."""
    app.config["TESTING"] = True

    # Rediriger la DB et les rapports vers tmp_path
    app_module.DB_PATH      = str(tmp_path / "test.db")
    app_module.REPORTS_DIR  = str(tmp_path / "reports")
    os.makedirs(app_module.REPORTS_DIR, exist_ok=True)

    init_db()

    with app.test_client() as c:
        yield c


# ─── Tests des routes principales ─────────────────────────────────────────────

def test_dashboard_accessible(client):
    """La page principale doit retourner 200."""
    resp = client.get("/")
    assert resp.status_code == 200


def test_api_scans_vide(client):
    """GET /api/scans sans aucun scan doit retourner une liste vide."""
    resp = client.get("/api/scans")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert isinstance(data, list)


def test_api_scan_post_sans_url(client):
    """POST /api/scan sans URL doit retourner 400."""
    resp = client.post(
        "/api/scan",
        data=json.dumps({}),
        content_type="application/json"
    )
    assert resp.status_code == 400
    data = json.loads(resp.data)
    assert "error" in data


def test_api_scan_post_avec_url(client):
    """POST /api/scan avec URL valide doit retourner un scan_id."""
    resp = client.post(
        "/api/scan",
        data=json.dumps({"url": "http://exemple.com", "modules": ["headers"]}),
        content_type="application/json"
    )
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert "scan_id" in data
    assert len(data["scan_id"]) == 8


def test_api_scan_auto_prefixe_http(client):
    """Une URL sans http:// doit être acceptée et préfixée automatiquement."""
    resp = client.post(
        "/api/scan",
        data=json.dumps({"url": "exemple.com", "modules": ["headers"]}),
        content_type="application/json"
    )
    assert resp.status_code == 200


def test_api_scan_status_inconnu(client):
    """GET /api/scan/<id_inconnu> doit retourner 404."""
    resp = client.get("/api/scan/xxxxxxxx")
    assert resp.status_code == 404


def test_api_scan_results_inconnu(client):
    """GET /api/scan/<id_inconnu>/results doit retourner 404."""
    resp = client.get("/api/scan/xxxxxxxx/results")
    assert resp.status_code == 404


def test_report_path_traversal(client):
    """La route /report/ doit bloquer les tentatives de path traversal."""
    resp = client.get("/report/../../../etc/passwd")
    assert resp.status_code in (403, 404)


# ─── Tests du module headers_checker ─────────────────────────────────────────

def test_check_headers_retourne_structure():
    """check_headers doit toujours retourner un dict avec 'module', 'findings', 'total'."""
    from modules.headers_checker import check_headers
    result = check_headers("http://httpbin.org/get", timeout=5)
    assert "module" in result
    assert "findings" in result
    assert "total" in result
    assert isinstance(result["findings"], list)


# ─── Tests du module cookies_cors_checker ────────────────────────────────────

def test_check_cookies_cors_retourne_structure():
    """check_cookies_cors doit retourner un dict valide même sur une URL inaccessible."""
    from modules.cookies_cors_checker import check_cookies_cors
    result = check_cookies_cors("http://127.0.0.1:19999", timeout=2)
    assert "module" in result
    assert "findings" in result
    assert result["module"] == "Cookies & CORS"
