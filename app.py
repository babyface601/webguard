"""
WebGuard – Scanner de Vulnérabilités Web (OWASP Top 10)
Application Flask principale — interface de lancement et résultats.
USAGE LÉGAL UNIQUEMENT – Scanner uniquement des cibles autorisées.
"""

import os
import sys
import uuid
import json
import logging
import sqlite3
import threading

sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, request, jsonify, render_template, send_file
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from modules.headers_checker      import check_headers
from modules.ssl_checker          import check_ssl
from modules.sql_scanner          import scan_sqli
from modules.xss_scanner          import scan_xss
from modules.dir_csrf_scanner     import scan_directories, scan_csrf
from modules.cookies_cors_checker import check_cookies_cors
from modules.reporter             import generate_report

# ─── Configuration ────────────────────────────────────────────────────────────

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
DB_PATH     = os.path.join(BASE_DIR, "webguard.db")
DEBUG_MODE  = os.getenv("FLASK_DEBUG", "false").lower() == "true"

os.makedirs(REPORTS_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.DEBUG if DEBUG_MODE else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("webguard")

app = Flask(__name__)
SCANS: dict = {}   # cache en mémoire (rapide)

# ─── Base de données SQLite ───────────────────────────────────────────────────

def init_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id           TEXT PRIMARY KEY,
            url          TEXT NOT NULL,
            status       TEXT NOT NULL,
            total_findings INTEGER DEFAULT 0,
            report_name  TEXT,
            started_at   TEXT,
            finished_at  TEXT,
            results_json TEXT
        )
    """)
    con.commit()
    con.close()
    logger.info("Base de données initialisée : %s", DB_PATH)


def save_scan_to_db(scan: dict):
    try:
        con = sqlite3.connect(DB_PATH)
        con.execute("""
            INSERT OR REPLACE INTO scans
              (id, url, status, total_findings, report_name, started_at, finished_at, results_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan["id"], scan["url"], scan["status"],
            scan.get("total_findings", 0), scan.get("report_name"),
            scan.get("started_at"), scan.get("finished_at"),
            json.dumps(scan.get("results", []))
        ))
        con.commit()
        con.close()
    except Exception as e:
        logger.warning("Erreur sauvegarde DB : %s", e)


def load_history_from_db() -> list:
    try:
        con = sqlite3.connect(DB_PATH)
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "SELECT * FROM scans ORDER BY finished_at DESC LIMIT 100"
        ).fetchall()
        con.close()
        history = []
        for row in rows:
            entry = dict(row)
            entry["results"] = json.loads(entry.get("results_json") or "[]")
            history.append(entry)
        return history
    except Exception as e:
        logger.warning("Erreur lecture historique : %s", e)
        return []


# ─── Logique de scan ─────────────────────────────────────────────────────────

def run_scan(scan_id: str, target_url: str, selected_modules: list):
    SCANS[scan_id]["status"]     = "running"
    SCANS[scan_id]["started_at"] = datetime.now().strftime("%H:%M:%S")
    results = []

    MODULE_MAP = {
        "headers":      ("Headers Checker",   lambda: check_headers(target_url)),
        "ssl":          ("SSL/TLS Checker",   lambda: check_ssl(target_url)),
        "sqli":         ("SQL Injection",     lambda: scan_sqli(target_url)),
        "xss":          ("XSS Scanner",       lambda: scan_xss(target_url)),
        "dirs":         ("Directory Scanner", lambda: scan_directories(target_url)),
        "csrf":         ("CSRF Checker",      lambda: scan_csrf(target_url)),
        "cookies_cors": ("Cookies & CORS",    lambda: check_cookies_cors(target_url)),
    }

    active = {k: v for k, v in MODULE_MAP.items() if k in selected_modules}
    total  = len(active)
    done   = 0

    logger.info("Démarrage scan %s sur %s — modules : %s", scan_id, target_url, list(active))

    with ThreadPoolExecutor(max_workers=min(total, 4)) as ex:
        futures = {ex.submit(fn): (key, label) for key, (label, fn) in active.items()}
        for future in as_completed(futures):
            key, label = futures[future]
            done += 1
            SCANS[scan_id]["progress"]       = int(done / total * 100)
            SCANS[scan_id]["current_module"] = label
            try:
                result = future.result()
                results.append(result)
                logger.debug("Module %s terminé — %d finding(s)", label, result.get("total", 0))
            except Exception as e:
                logger.warning("Module %s erreur : %s", label, e)
                results.append({"module": label, "findings": [], "total": 0, "error": str(e)})

    # Générer le rapport HTML
    report_path, report_name = generate_report(target_url, results, REPORTS_DIR)
    total_findings = sum(r.get("total", 0) for r in results)

    SCANS[scan_id].update({
        "status":         "done",
        "progress":       100,
        "results":        results,
        "report_path":    report_path,
        "report_name":    report_name,
        "total_findings": total_findings,
        "finished_at":    datetime.now().strftime("%H:%M:%S"),
    })

    save_scan_to_db(SCANS[scan_id])
    logger.info("Scan %s terminé — %d finding(s)", scan_id, total_findings)


# ─── Routes Flask ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/scan", methods=["POST"])
def start_scan():
    data = request.json or {}
    url  = data.get("url", "").strip()
    mods = data.get("modules", ["headers", "ssl", "dirs", "csrf", "cookies_cors"])

    if not url:
        return jsonify({"error": "URL manquante"}), 400
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    scan_id = str(uuid.uuid4())[:8]
    SCANS[scan_id] = {
        "id": scan_id, "url": url, "status": "queued",
        "progress": 0, "current_module": "—",
        "results": [], "total_findings": 0,
        "report_path": None, "report_name": None,
    }
    threading.Thread(target=run_scan, args=(scan_id, url, mods), daemon=True).start()
    logger.info("Nouveau scan %s lancé → %s", scan_id, url)
    return jsonify({"scan_id": scan_id})


@app.route("/api/scan/<scan_id>")
def scan_status(scan_id):
    if scan_id not in SCANS:
        return jsonify({"error": "Scan inconnu"}), 404
    s = SCANS[scan_id]
    return jsonify({
        "id":             s["id"],
        "url":            s["url"],
        "status":         s["status"],
        "progress":       s["progress"],
        "current_module": s.get("current_module", "—"),
        "total_findings": s.get("total_findings", 0),
        "report_name":    s.get("report_name"),
        "finished_at":    s.get("finished_at"),
    })


@app.route("/api/scan/<scan_id>/results")
def scan_results(scan_id):
    # Chercher d'abord dans le cache mémoire, puis en DB
    s = SCANS.get(scan_id)
    if not s:
        rows = load_history_from_db()
        match = next((r for r in rows if r["id"] == scan_id), None)
        if not match or match["status"] != "done":
            return jsonify({"error": "Scan non terminé ou inconnu"}), 404
        s = match
    elif s["status"] != "done":
        return jsonify({"error": "Scan non terminé"}), 404

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for r in s.get("results", []):
        for f in r.get("findings", []):
            sev = f.get("severity", "INFO")
            counts[sev] = counts.get(sev, 0) + 1

    return jsonify({
        "results":     s["results"],
        "counts":      counts,
        "report_name": s.get("report_name"),
        "url":         s.get("url"),
        "finished_at": s.get("finished_at"),
    })


@app.route("/api/scans")
def list_scans():
    # Fusionner cache mémoire + historique DB (DB prioritaire pour les anciens scans)
    db_history = load_history_from_db()
    db_ids = {r["id"] for r in db_history}

    # Ajouter les scans en cours non encore en DB
    in_memory = [
        {"id": s["id"], "url": s["url"], "status": s["status"],
         "total_findings": s.get("total_findings", 0),
         "report_name": s.get("report_name"),
         "finished_at": s.get("finished_at")}
        for s in SCANS.values() if s["id"] not in db_ids
    ]

    combined = in_memory + [
        {"id": r["id"], "url": r["url"], "status": r["status"],
         "total_findings": r.get("total_findings", 0),
         "report_name": r.get("report_name"),
         "finished_at": r.get("finished_at")}
        for r in db_history
    ]
    return jsonify(combined)


@app.route("/report/<path:filename>")
def get_report(filename):
    safe_path = os.path.abspath(os.path.join(REPORTS_DIR, filename))
    if not safe_path.startswith(os.path.abspath(REPORTS_DIR) + os.sep):
        return "Accès refusé", 403
    if not os.path.isfile(safe_path):
        return "Rapport introuvable", 404
    return send_file(safe_path, mimetype="text/html")


# ─── Lancement ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    logger.info("🛡️  WebGuard démarré sur http://localhost:5001")
    logger.info("⚠️  Usage légal uniquement — cibles autorisées uniquement")
    app.run(debug=DEBUG_MODE, host="0.0.0.0", port=5001)
