"""
WebGuard – Module Directory Bruteforce + CSRF Checker
OWASP A01:2021 – Broken Access Control
Découvre les répertoires/fichiers sensibles exposés et vérifie la protection CSRF.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
urllib3.disable_warnings()

# Wordlist de base (répertoires/fichiers courants sensibles)
COMMON_PATHS = [
    "admin/", "administrator/", "login/", "wp-admin/", "phpmyadmin/",
    "phpMyAdmin/", "pma/", "mysql/", "db/", "database/",
    ".git/", ".env", ".htaccess", ".htpasswd", "config.php",
    "config.yml", "config.yaml", "configuration.php", "settings.py",
    "wp-config.php", "web.config", "application.properties",
    "backup/", "backups/", "bak/", "old/", "tmp/", "temp/",
    "upload/", "uploads/", "files/", "file/", "media/",
    "api/", "api/v1/", "api/v2/", "swagger/", "swagger-ui/",
    "docs/", "doc/", "documentation/", "readme.txt", "README.md",
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    "server-status", "server-info",
    "test/", "tests/", "demo/", "dev/", "development/",
    "console/", "shell/", "cmd/", "exec/",
    "install/", "setup/", "installer/",
    "logs/", "log/", "error_log", "access_log",
    "secret/", "secrets/", "private/", "hidden/",
]

SENSITIVE_EXTENSIONS = [".bak", ".sql", ".tar.gz", ".zip", ".old", ".orig"]


def check_path(base_url, path, session, timeout=5):
    url = urljoin(base_url.rstrip("/") + "/", path)
    try:
        resp = session.get(url, timeout=timeout, verify=False,
                           allow_redirects=False)
        if resp.status_code in (200, 201, 204, 301, 302, 403):
            return {
                "path": path,
                "url": url,
                "status": resp.status_code,
                "size": len(resp.content)
            }
    except Exception:
        pass
    return None


def scan_directories(url, timeout=10, max_workers=15):
    findings = []
    session = requests.Session()
    session.headers.update({"User-Agent": "WebGuard-Scanner/1.0"})

    discovered = []

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(check_path, url, p, session, timeout): p
                   for p in COMMON_PATHS}
        for f in as_completed(futures):
            result = f.result()
            if result:
                discovered.append(result)

    # Classer par sévérité
    critical_paths = [
        ".git", ".env", "config", "wp-config", "phpmyadmin", "phpMyAdmin",
        ".htpasswd", "backup", "bak", "sql", "secret", "shell", "cmd", "exec"
    ]
    high_paths = [
        "admin", "administrator", "wp-admin", "console", "install", "setup",
        "logs", "log", "private", "hidden", "database", "db"
    ]

    for item in discovered:
        path_lower = item["path"].lower()
        severity = "INFO"
        for cp in critical_paths:
            if cp in path_lower:
                severity = "CRITICAL"
                break
        if severity == "INFO":
            for hp in high_paths:
                if hp in path_lower:
                    severity = "HIGH"
                    break
        if severity == "INFO":
            severity = "MEDIUM"

        status_label = {200: "Accessible", 403: "Forbidden (existe)", 301: "Redirect", 302: "Redirect"}.get(item["status"], str(item["status"]))

        findings.append({
            "type": "EXPOSED_PATH",
            "severity": severity,
            "path": item["path"],
            "url": item["url"],
            "status_code": item["status"],
            "status_label": status_label,
            "size": item["size"],
            "description": f"Chemin sensible découvert : {item['url']} [{item['status']} – {status_label}]",
            "recommendation": "Restreindre l'accès via la configuration du serveur web (Nginx/Apache). Supprimer les fichiers de backup et de configuration exposés.",
            "owasp": "A01:2021 – Broken Access Control"
        })

    return {
        "module": "Directory Scanner",
        "url": url,
        "paths_tested": len(COMMON_PATHS),
        "findings": findings,
        "total": len(findings),
        "error": None
    }


# ─── CSRF Checker ────────────────────────────────────────────────────────────

def scan_csrf(url, timeout=10):
    findings = []
    session = requests.Session()
    session.headers.update({"User-Agent": "WebGuard-Scanner/1.0"})

    try:
        resp = session.get(url, timeout=timeout, verify=False)
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")

        for form in forms:
            method = form.attrs.get("method", "get").lower()
            if method != "post":
                continue

            inputs = form.find_all("input")
            has_csrf_token = False

            csrf_names = ["csrf", "token", "_token", "csrftoken",
                          "csrf_token", "authenticity_token", "_csrf", "nonce"]

            for inp in inputs:
                inp_name  = inp.attrs.get("name", "").lower()
                inp_type  = inp.attrs.get("type", "").lower()
                if any(c in inp_name for c in csrf_names) or inp_type == "hidden":
                    # Vérifier si c'est vraiment un token CSRF
                    if any(c in inp_name for c in csrf_names):
                        has_csrf_token = True
                        break

            if not has_csrf_token:
                action = form.attrs.get("action", url)
                findings.append({
                    "type": "MISSING_CSRF_TOKEN",
                    "severity": "HIGH",
                    "location": f"Formulaire POST : {action}",
                    "description": f"Formulaire POST sans token CSRF détecté ({action}). Susceptible aux attaques Cross-Site Request Forgery.",
                    "recommendation": "Ajouter un token CSRF unique et aléatoire dans chaque formulaire POST. Vérifier le token côté serveur à chaque soumission.",
                    "owasp": "A01:2021 – Broken Access Control (CSRF)"
                })

        return {
            "module": "CSRF Checker",
            "url": url,
            "forms_found": len(forms),
            "findings": findings,
            "total": len(findings),
            "error": None
        }

    except Exception as e:
        return {"module": "CSRF Checker", "url": url,
                "findings": [], "total": 0, "error": str(e)}
