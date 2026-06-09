"""
WebGuard – Module Reporter
Génère un rapport HTML professionnel à partir des résultats de scan.
"""

from datetime import datetime
import json
import os

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLOR = {
    "CRITICAL": ("#7f1d1d", "#ef4444", "#fca5a5"),
    "HIGH":     ("#7c2d12", "#f97316", "#fdba74"),
    "MEDIUM":   ("#713f12", "#eab308", "#fde047"),
    "LOW":      ("#14532d", "#22c55e", "#86efac"),
    "INFO":     ("#1e3a5f", "#3b82f6", "#93c5fd"),
}


def count_by_severity(all_findings):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in all_findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def compute_score(counts):
    """Score de sécurité sur 100 (100 = parfait, 0 = critique)."""
    penalties = counts["CRITICAL"]*25 + counts["HIGH"]*10 + counts["MEDIUM"]*5 + counts["LOW"]*2
    score = max(0, 100 - penalties)
    if score >= 80:
        grade, color = "A", "#22c55e"
    elif score >= 60:
        grade, color = "B", "#84cc16"
    elif score >= 40:
        grade, color = "C", "#eab308"
    elif score >= 20:
        grade, color = "D", "#f97316"
    else:
        grade, color = "F", "#ef4444"
    return score, grade, color


def severity_badge(severity):
    bg, text, _ = SEVERITY_COLOR.get(severity, SEVERITY_COLOR["INFO"])
    return f'<span style="background:{bg};color:{text};padding:2px 10px;border-radius:20px;font-size:.7rem;font-weight:700">{severity}</span>'


def generate_report(target_url, scan_results, output_dir="reports"):
    os.makedirs(output_dir, exist_ok=True)

    all_findings = []
    for result in scan_results:
        for f in result.get("findings", []):
            f["_module"] = result.get("module", "")
            all_findings.append(f)

    all_findings.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity", "INFO"), 4))

    counts = count_by_severity(all_findings)
    score, grade, grade_color = compute_score(counts)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = f"webguard_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    filepath = os.path.join(output_dir, filename)

    # Modules summary
    modules_html = ""
    for r in scan_results:
        status = "✓" if not r.get("error") else "✗"
        color  = "#22c55e" if not r.get("error") else "#ef4444"
        modules_html += f"""
        <tr>
          <td style="padding:.5rem .75rem;color:#e2e8f0">{r.get('module','')}</td>
          <td style="padding:.5rem .75rem;color:{color};font-weight:700">{status}</td>
          <td style="padding:.5rem .75rem;color:#94a3b8">{r.get('total',0)} finding(s)</td>
          <td style="padding:.5rem .75rem;color:#64748b;font-size:.8rem">{r.get('error') or 'OK'}</td>
        </tr>"""

    # Findings HTML
    findings_html = ""
    if not all_findings:
        findings_html = '<p style="color:#22c55e;text-align:center;padding:2rem">✓ Aucune vulnérabilité détectée</p>'
    else:
        for i, f in enumerate(all_findings, 1):
            sev = f.get("severity", "INFO")
            bg, text, light = SEVERITY_COLOR.get(sev, SEVERITY_COLOR["INFO"])
            findings_html += f"""
            <div style="background:#1e293b;border:1px solid #334155;border-left:4px solid {text};border-radius:8px;padding:1rem 1.25rem;margin-bottom:.75rem">
              <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:1rem;margin-bottom:.6rem">
                <div>
                  <span style="font-weight:700;color:#f1f5f9">#{i} — {f.get('type','').replace('_',' ')}</span>
                  <span style="margin-left:.5rem;font-size:.7rem;color:#64748b">{f.get('_module','')}</span>
                </div>
                {severity_badge(sev)}
              </div>
              <p style="color:#94a3b8;font-size:.85rem;margin-bottom:.5rem">{f.get('description','')}</p>
              {'<p style="color:#94a3b8;font-size:.8rem;margin-bottom:.4rem"><b style="color:#60a5fa">Localisation :</b> ' + f.get('location','') + '</p>' if f.get('location') else ''}
              {'<p style="color:#94a3b8;font-size:.8rem;margin-bottom:.4rem"><b style="color:#f87171">Payload :</b> <code style="background:#0f172a;padding:1px 6px;border-radius:3px">' + f.get('payload','') + '</code></p>' if f.get('payload') else ''}
              <div style="background:#0f172a;border-radius:6px;padding:.6rem .8rem;margin-top:.5rem">
                <b style="color:#22c55e;font-size:.8rem">✓ Recommandation :</b>
                <p style="color:#86efac;font-size:.8rem;margin:.2rem 0 0">{f.get('recommendation','')}</p>
              </div>
              <p style="color:#475569;font-size:.7rem;margin-top:.4rem">{f.get('owasp','')}</p>
            </div>"""

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>WebGuard – Rapport de Sécurité – {target_url}</title>
<style>
  *{{margin:0;padding:0;box-sizing:border-box}}
  body{{font-family:'Segoe UI',Arial,sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem}}
  h1,h2,h3{{color:#f1f5f9}}
  table{{width:100%;border-collapse:collapse}}
  tr:nth-child(even){{background:#162032}}
  code{{font-family:monospace}}
  @media print{{body{{background:#fff;color:#000}}}}
</style>
</head>
<body>
<div style="max-width:960px;margin:0 auto">

  <!-- Header -->
  <div style="background:#1e293b;border-radius:12px;padding:1.5rem 2rem;margin-bottom:1.5rem;border:1px solid #334155">
    <div style="display:flex;align-items:center;justify-content:space-between">
      <div>
        <h1 style="font-size:1.5rem;margin-bottom:.25rem">🛡️ WebGuard — Rapport de Sécurité</h1>
        <p style="color:#64748b;font-size:.85rem">Scan automatisé OWASP Top 10</p>
      </div>
      <div style="text-align:right">
        <div style="font-size:3rem;font-weight:900;color:{grade_color}">{grade}</div>
        <div style="font-size:.75rem;color:#64748b">Score : {score}/100</div>
      </div>
    </div>
    <hr style="border-color:#334155;margin:1rem 0">
    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;font-size:.8rem">
      <div><span style="color:#64748b">Cible : </span><span style="color:#60a5fa">{target_url}</span></div>
      <div><span style="color:#64748b">Date : </span><span>{now}</span></div>
      <div><span style="color:#64748b">Findings : </span><span style="color:#f97316;font-weight:700">{len(all_findings)} vulnérabilité(s)</span></div>
    </div>
  </div>

  <!-- Score -->
  <div style="display:grid;grid-template-columns:repeat(5,1fr);gap:.75rem;margin-bottom:1.5rem">
    {''.join(f"""<div style="background:#1e293b;border:1px solid #334155;border-top:3px solid {SEVERITY_COLOR[s][1]};border-radius:8px;padding:.75rem;text-align:center">
      <div style="font-size:1.5rem;font-weight:700;color:{SEVERITY_COLOR[s][1]}">{counts[s]}</div>
      <div style="font-size:.65rem;color:#64748b;text-transform:uppercase">{s}</div>
    </div>""" for s in ['CRITICAL','HIGH','MEDIUM','LOW','INFO'])}
  </div>

  <!-- Modules -->
  <div style="background:#1e293b;border:1px solid #334155;border-radius:10px;padding:1.25rem;margin-bottom:1.5rem">
    <h2 style="font-size:1rem;margin-bottom:.75rem">📋 Modules exécutés</h2>
    <table><thead><tr style="border-bottom:1px solid #334155">
      <th style="padding:.4rem .75rem;text-align:left;color:#64748b;font-size:.75rem">Module</th>
      <th style="padding:.4rem .75rem;text-align:left;color:#64748b;font-size:.75rem">Statut</th>
      <th style="padding:.4rem .75rem;text-align:left;color:#64748b;font-size:.75rem">Résultat</th>
      <th style="padding:.4rem .75rem;text-align:left;color:#64748b;font-size:.75rem">Info</th>
    </tr></thead><tbody>{modules_html}</tbody></table>
  </div>

  <!-- Findings -->
  <div style="background:#1e293b;border:1px solid #334155;border-radius:10px;padding:1.25rem;margin-bottom:1.5rem">
    <h2 style="font-size:1rem;margin-bottom:.75rem">🔍 Vulnérabilités détectées ({len(all_findings)})</h2>
    {findings_html}
  </div>

  <!-- Footer -->
  <p style="text-align:center;color:#334155;font-size:.75rem">
    WebGuard Scanner — Rapport généré le {now} — BEVA Jean Gynolla — ENI Fianarantsoa
    <br>⚠️ Usage légal uniquement. Scanner uniquement des cibles avec autorisation explicite.
  </p>
</div>
</body>
</html>"""

    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write(html)

    return filepath, filename
