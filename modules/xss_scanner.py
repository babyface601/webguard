"""
WebGuard – Module XSS Scanner
OWASP A03:2021 – Injection (Cross-Site Scripting)
Détecte les vulnérabilités XSS réfléchies dans les formulaires et paramètres URL.
USAGE LÉGAL UNIQUEMENT.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import urllib3
urllib3.disable_warnings()

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    '<body onload=alert(1)>',
    '<<SCRIPT>alert("XSS");//<</SCRIPT>',
    '<ScRiPt>alert(1)</ScRiPt>',
    '%3Cscript%3Ealert(1)%3C/script%3E',
]

# Marqueur unique pour détecter si le payload est reflété sans encodage
XSS_MARKER = "WGXSS7TEST"


def get_forms(url, session, timeout=10):
    try:
        resp = session.get(url, timeout=timeout, verify=False)
        soup = BeautifulSoup(resp.text, "html.parser")
        return soup.find_all("form"), resp.text
    except Exception:
        return [], ""


def get_form_details(form, base_url):
    action = form.attrs.get("action", "").strip()
    return {
        "action": urljoin(base_url, action) if action else base_url,
        "method": form.attrs.get("method", "get").lower(),
        "inputs": [
            {"type": i.attrs.get("type", "text"),
             "name": i.attrs.get("name", ""),
             "value": i.attrs.get("value", "test")}
            for i in form.find_all(["input", "textarea"])
            if i.attrs.get("name")
        ]
    }


def is_reflected(payload, response_text):
    """Vérifie si le payload est réfléchi sans encodage HTML."""
    return payload in response_text or XSS_MARKER in response_text


def submit_form(details, payload, session, timeout=8):
    data = {}
    for inp in details["inputs"]:
        if inp["type"] in ("hidden", "submit", "button"):
            data[inp["name"]] = inp["value"]
        else:
            data[inp["name"]] = payload
    try:
        if details["method"] == "post":
            resp = session.post(details["action"], data=data,
                                timeout=timeout, verify=False)
        else:
            resp = session.get(details["action"], params=data,
                               timeout=timeout, verify=False)
        return resp
    except Exception:
        return None


def scan_xss(url, timeout=10):
    findings = []
    session = requests.Session()
    session.headers.update({"User-Agent": "WebGuard-Scanner/1.0"})

    tested = 0
    vulnerable_forms = set()
    vulnerable_params = set()

    try:
        forms, orig_text = get_forms(url, session, timeout)

        # ── Test des formulaires ──────────────────────────────────────────────
        for form in forms:
            details = get_form_details(form, url)
            form_key = details["action"]
            if form_key in vulnerable_forms:
                continue
            for payload in XSS_PAYLOADS:
                tested += 1
                resp = submit_form(details, payload, session, timeout)
                if resp and is_reflected(payload, resp.text):
                    if form_key not in vulnerable_forms:
                        vulnerable_forms.add(form_key)
                        findings.append({
                            "type": "XSS_REFLECTED",
                            "severity": "HIGH",
                            "location": f"Formulaire : {details['action']} ({details['method'].upper()})",
                            "payload": payload,
                            "description": f"XSS réfléchi détecté : le payload est retourné non-encodé dans la réponse HTML.",
                            "recommendation": "Encoder toutes les sorties HTML (htmlspecialchars en PHP, escape en Python/Jinja2). Mettre en place une Content-Security-Policy stricte.",
                            "owasp": "A03:2021 – Injection (XSS)"
                        })
                        break

        # ── Test des paramètres URL ───────────────────────────────────────────
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param_name in params:
            if param_name in vulnerable_params:
                continue
            for payload in XSS_PAYLOADS:
                tested += 1
                test_params = {param_name: payload}
                try:
                    resp = session.get(url, params=test_params,
                                       timeout=timeout, verify=False)
                    if is_reflected(payload, resp.text):
                        if param_name not in vulnerable_params:
                            vulnerable_params.add(param_name)
                            findings.append({
                                "type": "XSS_REFLECTED",
                                "severity": "HIGH",
                                "location": f"Paramètre URL : ?{param_name}=",
                                "payload": payload,
                                "description": f"XSS réfléchi dans le paramètre GET '{param_name}'.",
                                "recommendation": "Valider et encoder les paramètres GET avant tout affichage dans la page.",
                                "owasp": "A03:2021 – Injection (XSS)"
                            })
                            break
                except Exception:
                    pass

        return {
            "module": "XSS Scanner",
            "url": url,
            "forms_found": len(forms),
            "tests_run": tested,
            "findings": findings,
            "total": len(findings),
            "error": None
        }

    except requests.exceptions.ConnectionError:
        return {"module": "XSS Scanner", "url": url,
                "findings": [], "total": 0, "error": "Connexion impossible"}
    except Exception as e:
        return {"module": "XSS Scanner", "url": url,
                "findings": [], "total": 0, "error": str(e)}
