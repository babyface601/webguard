"""
WebGuard – Module SQL Injection Scanner
OWASP A03:2021 – Injection
Teste les formulaires et paramètres URL pour détecter les vulnérabilités SQLi.
USAGE LÉGAL UNIQUEMENT – À utiliser uniquement sur des cibles dont vous avez l'autorisation.
"""

import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urlencode, urlparse, parse_qs, urljoin
import urllib3
urllib3.disable_warnings()

# Payloads de détection (non-destructifs)
SQL_PAYLOADS = [
    "'",
    "''",
    "`",
    "\"",
    "\\",
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 'x'='x",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "' UNION SELECT NULL--",
    "'; SELECT SLEEP(0)--",
    "1 AND 1=1",
    "1 AND 1=2",
]

# Signatures d'erreurs SQL dans les réponses
SQL_ERRORS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"MySQLSyntaxErrorException",
    r"valid MySQL result",
    r"check the manual that corresponds to your MySQL",
    r"ORA-[0-9]{5}",
    r"Oracle.*Driver",
    r"Warning.*oci_",
    r"Microsoft SQL Server",
    r"Unclosed quotation mark",
    r"SQLSTATE\[",
    r"PostgreSQL.*ERROR",
    r"pg_query\(\)",
    r"SQLite.*error",
    r"syntax error.*sqlite",
    r"SQLITE_ERROR",
    r"Syntax error.*in query expression",
    r"Data type mismatch",
    r"You have an error in your SQL syntax",
    r"supplied argument is not a valid MySQL",
    r"Column count doesn't match",
]


def get_forms(url, session, timeout=10):
    try:
        resp = session.get(url, timeout=timeout, verify=False)
        soup = BeautifulSoup(resp.text, "html.parser")
        return soup.find_all("form")
    except Exception:
        return []


def get_form_details(form, base_url):
    details = {}
    action = form.attrs.get("action", "").strip()
    details["action"] = urljoin(base_url, action) if action else base_url
    details["method"] = form.attrs.get("method", "get").lower()
    details["inputs"] = []
    for inp in form.find_all(["input", "textarea", "select"]):
        inp_type  = inp.attrs.get("type", "text")
        inp_name  = inp.attrs.get("name", "")
        inp_value = inp.attrs.get("value", "test")
        if inp_name:
            details["inputs"].append({
                "type":  inp_type,
                "name":  inp_name,
                "value": inp_value
            })
    return details


def detect_sqli_in_response(response_text, original_text):
    for pattern in SQL_ERRORS:
        if re.search(pattern, response_text, re.IGNORECASE):
            match = re.search(pattern, response_text, re.IGNORECASE)
            return True, match.group(0)
    # Détection par différence de longueur importante (heuristique)
    if abs(len(response_text) - len(original_text)) > 500:
        return False, None
    return False, None


def test_form(form_details, payload, session, original_resp, timeout=8):
    data = {}
    for inp in form_details["inputs"]:
        if inp["type"] in ("hidden", "submit", "button"):
            data[inp["name"]] = inp["value"]
        elif inp["name"]:
            data[inp["name"]] = payload

    try:
        if form_details["method"] == "post":
            resp = session.post(form_details["action"], data=data,
                                timeout=timeout, verify=False)
        else:
            resp = session.get(form_details["action"], params=data,
                               timeout=timeout, verify=False)
        return resp
    except Exception:
        return None


def test_url_params(url, payload, session, timeout=8):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        return None, {}
    injected = {k: payload for k in params}
    try:
        resp = session.get(url, params=injected, timeout=timeout, verify=False)
        return resp, injected
    except Exception:
        return None, {}


def scan_sqli(url, timeout=10):
    findings = []
    session = requests.Session()
    session.headers.update({"User-Agent": "WebGuard-Scanner/1.0"})

    tested = 0
    vulnerable_forms = set()
    vulnerable_params = set()

    try:
        # Réponse originale pour comparaison
        orig_resp = session.get(url, timeout=timeout, verify=False)
        orig_text = orig_resp.text

        # ── Test des formulaires ──────────────────────────────────────────────
        forms = get_forms(url, session, timeout)
        for form in forms:
            details = get_form_details(form, url)
            form_key = details["action"]
            if form_key in vulnerable_forms:
                continue
            for payload in SQL_PAYLOADS:
                tested += 1
                resp = test_form(details, payload, session, orig_text, timeout)
                if resp:
                    found, error_str = detect_sqli_in_response(resp.text, orig_text)
                    if found and form_key not in vulnerable_forms:
                        vulnerable_forms.add(form_key)
                        findings.append({
                            "type": "SQL_INJECTION",
                            "severity": "CRITICAL",
                            "location": f"Formulaire : {details['action']} (méthode {details['method'].upper()})",
                            "payload": payload,
                            "error_detected": error_str,
                            "description": f"Injection SQL détectée dans le formulaire {details['action']}. Erreur SQL exposée dans la réponse.",
                            "recommendation": "Utiliser des requêtes préparées (prepared statements) et des ORM. Ne jamais concaténer des entrées utilisateur dans les requêtes SQL.",
                            "owasp": "A03:2021 – Injection"
                        })
                        break

        # ── Test des paramètres URL ───────────────────────────────────────────
        parsed = urlparse(url)
        if parsed.query:
            for payload in SQL_PAYLOADS:
                tested += 1
                resp, injected = test_url_params(url, payload, session, timeout)
                if resp:
                    found, error_str = detect_sqli_in_response(resp.text, orig_text)
                    param_key = str(list(injected.keys()))
                    if found and param_key not in vulnerable_params:
                        vulnerable_params.add(param_key)
                        findings.append({
                            "type": "SQL_INJECTION",
                            "severity": "CRITICAL",
                            "location": f"Paramètre URL : {list(injected.keys())}",
                            "payload": payload,
                            "error_detected": error_str,
                            "description": f"Injection SQL détectée dans les paramètres URL : {list(injected.keys())}",
                            "recommendation": "Valider et assainir tous les paramètres GET. Utiliser des requêtes préparées.",
                            "owasp": "A03:2021 – Injection"
                        })
                        break

        return {
            "module": "SQL Injection Scanner",
            "url": url,
            "forms_found": len(forms),
            "tests_run": tested,
            "findings": findings,
            "total": len(findings),
            "error": None
        }

    except requests.exceptions.ConnectionError:
        return {"module": "SQL Injection Scanner", "url": url,
                "findings": [], "total": 0, "error": "Connexion impossible"}
    except Exception as e:
        return {"module": "SQL Injection Scanner", "url": url,
                "findings": [], "total": 0, "error": str(e)}
