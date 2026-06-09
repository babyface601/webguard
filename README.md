# 🛡️ WebGuard — Scanner de Vulnérabilités Web OWASP

> Projet portfolio – Cybersécurité / Administration Système  
> Stack : Python · Flask · Requests · BeautifulSoup · SQLite

## Présentation

WebGuard est un scanner automatisé de vulnérabilités web basé sur l'OWASP Top 10.  
Il analyse une URL cible, détecte les failles de sécurité et génère un rapport HTML professionnel avec score de sécurité.

## Fonctionnalités

- **7 modules de détection** couvrant l'OWASP Top 10
- **Score de sécurité** calculé selon la criticité des findings (0–100)
- **Visualisation interactive** — filtrage par sévérité (CRITICAL / HIGH / MEDIUM / LOW / INFO), modules accordéon
- **Historique persistant** — tous les scans sont sauvegardés en SQLite, accessibles après redémarrage
- **Rapports HTML** générés automatiquement par scan
- **Scan parallèle** — jusqu'à 4 modules simultanés (ThreadPoolExecutor)

## Modules de détection

| Module | Vulnérabilité OWASP | Ce qui est détecté |
|--------|-------------------|--------------------|
| `headers_checker.py` | A05 – Security Misconfiguration | Headers manquants (HSTS, CSP, X-Frame-Options…) + headers dangereux (Server, X-Powered-By) |
| `ssl_checker.py` | A02 – Cryptographic Failures | Certificat expiré, protocoles faibles (SSLv3, TLS 1.0/1.1), chiffrements vulnérables |
| `sql_scanner.py` | A03 – Injection | Injection SQL (erreurs de base de données, payloads classiques) |
| `xss_scanner.py` | A03 – Injection (XSS) | XSS réfléchi dans les paramètres GET/POST |
| `dir_csrf_scanner.py` | A01 – Broken Access Control | Répertoires exposés (.git, admin, backup…) + tokens CSRF manquants |
| `cookies_cors_checker.py` | A01, A05 | Cookies sans Secure/HttpOnly/SameSite, CORS wildcard, CORS origin reflection, open redirect |
| `reporter.py` | — | Génération du rapport HTML avec score et détail des findings |

## Lancement

```bash
# 1. Cloner le repo
git clone https://github.com/babyface601/webguard.git
cd webguard

# 2. Installer les dépendances
pip install -r requirements.txt

# 3. Lancer l'application
python app.py
# Ouvrir : http://localhost:5001
```

## Configuration

```bash
# Activer le mode debug (optionnel)
# Windows
set FLASK_DEBUG=true

# Linux / macOS
export FLASK_DEBUG=true
```

## Structure

```
webguard/
├── app.py                      # Serveur Flask — routes, scan, SQLite
├── modules/
│   ├── headers_checker.py      # A05 – Headers de sécurité
│   ├── ssl_checker.py          # A02 – SSL/TLS
│   ├── sql_scanner.py          # A03 – SQL Injection
│   ├── xss_scanner.py          # A03 – XSS
│   ├── dir_csrf_scanner.py     # A01 – Répertoires + CSRF
│   ├── cookies_cors_checker.py # A01/A05 – Cookies & CORS
│   └── reporter.py             # Génération rapport HTML
├── templates/
│   └── dashboard.html          # Interface web (Jinja2)
├── reports/                    # Rapports HTML générés (ignoré par git)
├── webguard.db                 # Historique SQLite (ignoré par git)
├── requirements.txt
└── .gitignore
```

## ⚠️ Avertissement légal

**Usage légal uniquement.**  
Ne scanner que des applications web dont vous avez l'autorisation explicite du propriétaire.  
L'utilisation non autorisée de cet outil constitue une infraction pénale.

## Auteur

BEVA Jean Gynolla — Informatique, ENI Fianarantsoa  
GitHub : [babyface601](https://github.com/babyface601)
