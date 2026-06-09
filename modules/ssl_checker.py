"""
WebGuard – Module SSL/TLS Checker
OWASP A02:2021 – Cryptographic Failures
Analyse la configuration SSL/TLS de la cible.
"""

import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse


def check_ssl(url, timeout=10):
    findings = []
    info = {}

    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme != "https":
        findings.append({
            "type": "NO_HTTPS",
            "severity": "CRITICAL",
            "description": "Le site n'utilise pas HTTPS — les données transitent en clair",
            "recommendation": "Migrer vers HTTPS avec un certificat TLS valide (Let's Encrypt gratuit)",
            "owasp": "A02:2021 – Cryptographic Failures"
        })
        return {
            "module": "SSL/TLS Checker",
            "url": url,
            "hostname": hostname,
            "findings": findings,
            "info": info,
            "total": len(findings),
            "error": None
        }

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher_name, _, bits = ssock.cipher()

                # Infos du certificat
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer  = dict(x[0] for x in cert.get("issuer", []))
                not_before = cert.get("notBefore", "")
                not_after  = cert.get("notAfter", "")

                info = {
                    "subject_cn": subject.get("commonName", "N/A"),
                    "issuer_cn":  issuer.get("organizationName", "N/A"),
                    "protocol":   protocol,
                    "cipher":     cipher_name,
                    "bits":       bits,
                    "not_before": not_before,
                    "not_after":  not_after,
                }

                # Expiration du certificat
                try:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    expiry = expiry.replace(tzinfo=timezone.utc)
                    now    = datetime.now(timezone.utc)
                    days_left = (expiry - now).days

                    if days_left < 0:
                        findings.append({
                            "type": "EXPIRED_CERTIFICATE",
                            "severity": "CRITICAL",
                            "description": f"Certificat SSL expiré depuis {abs(days_left)} jours",
                            "recommendation": "Renouveler immédiatement le certificat",
                            "owasp": "A02:2021 – Cryptographic Failures"
                        })
                    elif days_left < 30:
                        findings.append({
                            "type": "EXPIRING_SOON",
                            "severity": "HIGH",
                            "description": f"Certificat SSL expire dans {days_left} jours",
                            "recommendation": "Renouveler le certificat avant expiration",
                            "owasp": "A02:2021 – Cryptographic Failures"
                        })
                    info["days_left"] = days_left
                except Exception:
                    pass

                # Protocoles obsolètes
                if protocol in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                    findings.append({
                        "type": "WEAK_PROTOCOL",
                        "severity": "HIGH",
                        "description": f"Protocole obsolète détecté : {protocol}",
                        "recommendation": "Désactiver TLS 1.0 et 1.1, utiliser TLS 1.2+ uniquement",
                        "owasp": "A02:2021 – Cryptographic Failures"
                    })

                # Clé faible
                if bits and bits < 2048:
                    findings.append({
                        "type": "WEAK_KEY_SIZE",
                        "severity": "HIGH",
                        "description": f"Taille de clé faible : {bits} bits (recommandé : 2048+)",
                        "recommendation": "Utiliser une clé RSA de 2048 bits minimum ou ECDSA 256 bits",
                        "owasp": "A02:2021 – Cryptographic Failures"
                    })

                # Chiffrements faibles
                weak_ciphers = ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"]
                for wc in weak_ciphers:
                    if wc in cipher_name.upper():
                        findings.append({
                            "type": "WEAK_CIPHER",
                            "severity": "HIGH",
                            "description": f"Chiffrement faible utilisé : {cipher_name}",
                            "recommendation": "Utiliser des suites de chiffrement modernes (AES-GCM, ChaCha20)",
                            "owasp": "A02:2021 – Cryptographic Failures"
                        })
                        break

        return {
            "module": "SSL/TLS Checker",
            "url": url,
            "hostname": hostname,
            "findings": findings,
            "info": info,
            "total": len(findings),
            "error": None
        }

    except ssl.SSLCertVerificationError as e:
        findings.append({
            "type": "INVALID_CERTIFICATE",
            "severity": "CRITICAL",
            "description": f"Certificat invalide ou non approuvé : {str(e)[:100]}",
            "recommendation": "Obtenir un certificat signé par une autorité reconnue",
            "owasp": "A02:2021 – Cryptographic Failures"
        })
        return {"module": "SSL/TLS Checker", "url": url, "hostname": hostname,
                "findings": findings, "info": info, "total": len(findings), "error": None}
    except Exception as e:
        return {"module": "SSL/TLS Checker", "url": url, "hostname": hostname,
                "findings": [], "info": {}, "total": 0, "error": str(e)}
