# 🛡️ WebGuard — Scanner de Vulnérabilités Web OWASP

WebGuard est un scanner automatisé de vulnérabilités web basé sur l'**OWASP Top 10**, construit avec **Python/Flask**. Il analyse une URL cible, détecte les failles de sécurité par modules indépendants, et génère un rapport HTML avec score de sécurité.

---

## ✨ Fonctionnalités

- **7 modules OWASP** — Headers, SSL/TLS, SQLi, XSS, Directories, CSRF, Cookies & CORS
- **Score de sécurité** — note de 0 à 100 calculée selon la criticité des findings
- **Visualisation interactive** — filtrage par sévérité (CRITICAL / HIGH / MEDIUM / LOW / INFO), modules accordéon
- **Historique persistant** — tous les scans sauvegardés en SQLite, accessibles après redémarrage
- **Rapports HTML** — rapport complet généré automatiquement à chaque scan
- **Scan parallèle** — jusqu'à 4 modules simultanés (ThreadPoolExecutor)

---

## 🖥️ Aperçu

```
┌──────────────────────────────────────────────┐
│  🛡️ WebGuard   Scanner de Vulnérabilités Web │
├──────────────────────────────────────────────┤
│  🎯 Cible : https://exemple.com              │
│  [Headers] [SSL/TLS] [Cookies&CORS] [CSRF]   │
│  [XSS] [SQLi] [Directories]                  │
│  ▶ Lancer le scan                            │
├──────────────────────────────────────────────┤
│  Score de sécurité :  42 / 100  ⚠️ Moyen    │
│  CRITICAL: 2  HIGH: 5  MEDIUM: 8  LOW: 3    │
├──────────────────────────────────────────────┤
│  📦 Headers Checker         7 finding(s)     │
│    ▼ CRITICAL  Missing HSTS                  │
│    ▼ HIGH      Missing CSP                   │
│  📦 Cookies & CORS          3 finding(s)     │
│    ▼ HIGH      Cookie sans Secure            │
│    ▼ MEDIUM    CORS wildcard détecté         │
├──────────────────────────────────────────────┤
│  📁 Historique  |  ID  |  URL  |  Findings  │
│  done  exemple.com    18   📄 Voir           │
└──────────────────────────────────────────────┘
```

---

## 🚀 Installation

### Prérequis
- Python 3.8+
- pip

### Étapes

```bash
# 1. Cloner le repo
git clone https://github.com/babyface601/webguard.git
cd webguard

# 2. Installer les dépendances
pip install -r requirements.txt

# 3. Lancer l'application
python app.py
```

Ouvre **http://localhost:5001** dans ton navigateur.

---

## ⚙️ Configuration

```bash
# Activer le mode debug (optionnel)

# Windows
set FLASK_DEBUG=true

# Linux / macOS
export FLASK_DEBUG=true
```

> Par défaut, le mode debug est désactivé. Ne jamais l'activer en production.

---

## 🔍 Modules de détection

| Module | OWASP | Ce qui est détecté |
|--------|-------|--------------------|
| `headers_checker.py` | A05 – Security Misconfiguration | Headers manquants (HSTS, CSP, X-Frame-Options…), headers dangereux (Server, X-Powered-By) |
| `ssl_checker.py` | A02 – Cryptographic Failures | Certificat expiré, protocoles faibles (SSLv3, TLS 1.0/1.1), chiffrements vulnérables |
| `sql_scanner.py` | A03 – Injection | Injection SQL via erreurs de base de données et payloads classiques |
| `xss_scanner.py` | A03 – Injection | XSS réfléchi dans les paramètres GET/POST |
| `dir_csrf_scanner.py` | A01 – Broken Access Control | Répertoires exposés (`.git`, `admin`, `backup`…) et tokens CSRF manquants |
| `cookies_cors_checker.py` | A01, A05 | Cookies sans `Secure`/`HttpOnly`/`SameSite`, CORS wildcard, réflexion d'origine, open redirect |
| `reporter.py` | — | Génération du rapport HTML avec score de sécurité |

---

## 🗂️ Structure du projet

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

---

## 🛠️ Stack technique

| Couche | Technologie |
|---|---|
| Backend | Python 3, Flask |
| Scanning | `requests`, `BeautifulSoup`, `ssl` (stdlib) |
| Concurrence | `ThreadPoolExecutor` |
| Base de données | SQLite (`sqlite3` — stdlib) |
| Frontend | HTML5, CSS3, JavaScript vanilla |

---

## ⚠️ Avertissement légal

**Usage légal uniquement.**  
Ne scanner que des applications web dont vous avez l'autorisation explicite écrite du propriétaire.  
L'utilisation non autorisée de cet outil constitue une infraction pénale.

---

## 📄 Licence

MIT — libre d'utilisation et de modification.
