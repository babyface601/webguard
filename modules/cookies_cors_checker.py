"""
WebGuard – Module Cookies & CORS Checker
OWASP A01:2021 – Broken Access Control
OWASP A05:2021 – Security Misconfiguration
Vérifie les attributs de sécurité des cookies et la configuration CORS.
"""

import requests
import urllib3
from urllib.parse import urljoin, urlparse

urllib3.disable_warnings()


def _check_cookies(resp, findings):
    """Vérifie les attributs de sécurité des cookies."""
    raw_cookies = resp.headers.get_all("Set-Cookie") if hasattr(resp.headers, "get_all") else []
    # requests ne fournit pas get_all — on passe par raw
    raw_headers = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw, "headers") else []
    if not raw_headers:
        # Fallback : récupérer depuis resp.cookies
        for cookie in resp.cookies:
            attrs = []
            if not cookie.secure:
                attrs.append("Secure manquant")
            # requests ne parse pas HttpOnly/SameSite directement — on analyse l'en-tête brut
            raw_cookies = []

    # Analyser les Set-Cookie bruts depuis les headers de la réponse
    set_cookie_headers = []
    for k, v in resp.headers.items():
        if k.lower() == "set-cookie":
            set_cookie_headers.append(v)

    for cookie_str in set_cookie_headers:
        parts_lower = cookie_str.lower()
        name = cookie_str.split("=")[0].strip()

        if "secure" not in parts_lower:
            findings.append({
                "type": "INSECURE_COOKIE",
                "severity": "HIGH",
                "description": f"Cookie '{name}' sans attribut Secure — transmissible en HTTP clair",
                "recommendation": "Ajouter l'attribut Secure à tous les cookies de session",
                "owasp": "A05:2021 – Security Misconfiguration"
            })
        if "httponly" not in parts_lower:
            findings.append({
                "type": "COOKIE_NO_HTTPONLY",
                "severity": "MEDIUM",
                "description": f"Cookie '{name}' sans attribut HttpOnly — accessible via JavaScript (XSS)",
                "recommendation": "Ajouter HttpOnly pour empêcher l'accès JavaScript aux cookies",
                "owasp": "A05:2021 – Security Misconfiguration"
            })
        if "samesite" not in parts_lower:
            findings.append({
                "type": "COOKIE_NO_SAMESITE",
                "severity": "MEDIUM",
                "description": f"Cookie '{name}' sans attribut SameSite — vulnérable aux attaques CSRF",
                "recommendation": "Ajouter SameSite=Strict ou SameSite=Lax",
                "owasp": "A01:2021 – Broken Access Control"
            })
        elif "samesite=none" in parts_lower and "secure" not in parts_lower:
            findings.append({
                "type": "SAMESITE_NONE_WITHOUT_SECURE",
                "severity": "HIGH",
                "description": f"Cookie '{name}' : SameSite=None sans Secure est invalide et dangereux",
                "recommendation": "Utiliser SameSite=None uniquement avec l'attribut Secure",
                "owasp": "A05:2021 – Security Misconfiguration"
            })


def _check_cors(resp, url, findings):
    """Vérifie la configuration CORS."""
    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

    if acao == "*":
        if acac == "true":
            findings.append({
                "type": "CORS_WILDCARD_WITH_CREDENTIALS",
                "severity": "CRITICAL",
                "description": "CORS : Access-Control-Allow-Origin: * combiné avec Allow-Credentials: true — fuite de données authentifiées possible",
                "recommendation": "Ne jamais combiner wildcard (*) avec Allow-Credentials: true. Spécifier un domaine précis.",
                "owasp": "A01:2021 – Broken Access Control"
            })
        else:
            findings.append({
                "type": "CORS_WILDCARD",
                "severity": "MEDIUM",
                "description": "CORS : Access-Control-Allow-Origin: * — toute origine peut lire les réponses",
                "recommendation": "Restreindre à des domaines spécifiques si l'API n'est pas publique",
                "owasp": "A01:2021 – Broken Access Control"
            })
    elif acao:
        # Vérifier si l'origine est reflétée dynamiquement (misconfiguration courante)
        parsed = urlparse(url)
        test_origin = "https://evil.com"
        try:
            test_resp = requests.get(
                url, timeout=8, verify=False,
                headers={"Origin": test_origin, "User-Agent": "WebGuard-Scanner/1.0"}
            )
            reflected = test_resp.headers.get("Access-Control-Allow-Origin", "")
            if reflected == test_origin:
                findings.append({
                    "type": "CORS_ORIGIN_REFLECTION",
                    "severity": "HIGH",
                    "description": "CORS : le serveur reflète l'en-tête Origin sans validation — toute origine est acceptée",
                    "recommendation": "Valider l'Origin contre une whitelist stricte côté serveur",
                    "owasp": "A01:2021 – Broken Access Control"
                })
        except Exception:
            pass


def _check_open_redirect(url, findings):
    """Teste quelques patterns d'open redirect courants."""
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    test_payloads = [
        "?redirect=https://evil.com",
        "?url=https://evil.com",
        "?next=https://evil.com",
        "?return=https://evil.com",
        "?goto=https://evil.com",
    ]
    for payload in test_payloads:
        test_url = base + "/" + payload
        try:
            resp = requests.get(
                test_url, timeout=6, verify=False, allow_redirects=False,
                headers={"User-Agent": "WebGuard-Scanner/1.0"}
            )
            location = resp.headers.get("Location", "")
            if "evil.com" in location:
                findings.append({
                    "type": "OPEN_REDIRECT",
                    "severity": "HIGH",
                    "description": f"Open Redirect détecté sur '{payload}' → redirige vers {location}",
                    "recommendation": "Valider et filtrer les paramètres de redirection — utiliser uniquement des chemins relatifs ou une whitelist",
                    "owasp": "A01:2021 – Broken Access Control"
                })
                break  # Un seul finding suffit
        except Exception:
            pass


def check_cookies_cors(url: str, timeout: int = 10) -> dict:
    findings = []

    try:
        resp = requests.get(
            url, timeout=timeout, verify=False,
            headers={"User-Agent": "WebGuard-Scanner/1.0"}
        )

        _check_cookies(resp, findings)
        _check_cors(resp, url, findings)
        _check_open_redirect(url, findings)

        if not findings:
            findings.append({
                "type": "INFO",
                "severity": "INFO",
                "description": "Aucune mauvaise configuration cookies/CORS détectée",
                "recommendation": "Continuer à auditer régulièrement",
                "owasp": "—"
            })

        return {
            "module": "Cookies & CORS",
            "url": url,
            "findings": findings,
            "total": sum(1 for f in findings if f["severity"] != "INFO"),
            "error": None
        }

    except requests.exceptions.ConnectionError:
        return {"module": "Cookies & CORS", "url": url, "findings": [],
                "error": "Impossible de se connecter à la cible", "total": 0}
    except Exception as e:
        return {"module": "Cookies & CORS", "url": url, "findings": [],
                "error": str(e), "total": 0}
