"""
WebGuard – Module Headers Checker
OWASP A05:2021 – Security Misconfiguration
Vérifie la présence et la configuration des headers de sécurité HTTP.
"""

import requests
import urllib3
urllib3.disable_warnings()

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Force les connexions HTTPS (HSTS)",
        "severity": "HIGH",
        "recommendation": "Ajouter : Strict-Transport-Security: max-age=31536000; includeSubDomains"
    },
    "Content-Security-Policy": {
        "description": "Prévient les attaques XSS et injection de contenu",
        "severity": "HIGH",
        "recommendation": "Définir une politique CSP stricte : Content-Security-Policy: default-src 'self'"
    },
    "X-Content-Type-Options": {
        "description": "Empêche le MIME-type sniffing",
        "severity": "MEDIUM",
        "recommendation": "Ajouter : X-Content-Type-Options: nosniff"
    },
    "X-Frame-Options": {
        "description": "Prévient le clickjacking",
        "severity": "MEDIUM",
        "recommendation": "Ajouter : X-Frame-Options: DENY ou SAMEORIGIN"
    },
    "X-XSS-Protection": {
        "description": "Active le filtre XSS du navigateur (legacy)",
        "severity": "LOW",
        "recommendation": "Ajouter : X-XSS-Protection: 1; mode=block"
    },
    "Referrer-Policy": {
        "description": "Contrôle les informations envoyées dans le header Referer",
        "severity": "LOW",
        "recommendation": "Ajouter : Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "description": "Contrôle l'accès aux APIs du navigateur",
        "severity": "LOW",
        "recommendation": "Définir une Permissions-Policy pour limiter les APIs inutilisées"
    },
}

DANGEROUS_HEADERS = {
    "Server": {
        "description": "Expose la technologie et version du serveur",
        "severity": "MEDIUM",
        "recommendation": "Masquer ou généraliser la valeur du header Server"
    },
    "X-Powered-By": {
        "description": "Expose le langage/framework utilisé",
        "severity": "MEDIUM",
        "recommendation": "Supprimer le header X-Powered-By"
    },
    "X-AspNet-Version": {
        "description": "Expose la version d'ASP.NET",
        "severity": "MEDIUM",
        "recommendation": "Désactiver dans la config IIS"
    },
}


def check_headers(url, timeout=10):
    findings = []
    raw_headers = {}

    try:
        resp = requests.get(url, timeout=timeout, verify=False,
                            headers={"User-Agent": "WebGuard-Scanner/1.0"})
        raw_headers = dict(resp.headers)
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        # Vérifier les headers de sécurité manquants
        for header, info in SECURITY_HEADERS.items():
            if header.lower() not in headers_lower:
                findings.append({
                    "type": "MISSING_SECURITY_HEADER",
                    "header": header,
                    "severity": info["severity"],
                    "description": f"Header manquant : {header} — {info['description']}",
                    "recommendation": info["recommendation"],
                    "owasp": "A05:2021 – Security Misconfiguration"
                })

        # Vérifier les headers dangereux présents
        for header, info in DANGEROUS_HEADERS.items():
            if header.lower() in headers_lower:
                value = headers_lower[header.lower()]
                findings.append({
                    "type": "INFORMATION_DISCLOSURE",
                    "header": header,
                    "value": value,
                    "severity": info["severity"],
                    "description": f"Header dangereux présent : {header}: {value} — {info['description']}",
                    "recommendation": info["recommendation"],
                    "owasp": "A05:2021 – Security Misconfiguration"
                })

        # Vérifier HSTS si présent mais mal configuré
        hsts = headers_lower.get("strict-transport-security", "")
        if hsts and "max-age" in hsts:
            try:
                max_age = int(hsts.split("max-age=")[1].split(";")[0].strip())
                if max_age < 31536000:
                    findings.append({
                        "type": "WEAK_HSTS",
                        "header": "Strict-Transport-Security",
                        "severity": "MEDIUM",
                        "description": f"HSTS max-age trop court ({max_age}s). Recommandé : 31536000s (1 an)",
                        "recommendation": "Augmenter max-age à 31536000 minimum",
                        "owasp": "A02:2021 – Cryptographic Failures"
                    })
            except Exception:
                pass

        return {
            "module": "Headers Checker",
            "url": url,
            "status_code": resp.status_code,
            "raw_headers": raw_headers,
            "findings": findings,
            "total": len(findings),
            "error": None
        }

    except requests.exceptions.SSLError:
        return {"module": "Headers Checker", "url": url, "findings": [],
                "error": "Erreur SSL – certificat invalide ou expiré", "total": 0}
    except requests.exceptions.ConnectionError:
        return {"module": "Headers Checker", "url": url, "findings": [],
                "error": "Impossible de se connecter à la cible", "total": 0}
    except Exception as e:
        return {"module": "Headers Checker", "url": url, "findings": [],
                "error": str(e), "total": 0}
