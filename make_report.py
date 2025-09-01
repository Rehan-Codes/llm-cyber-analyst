import json, os, datetime

ART = "run_artifacts"

def load(name):
    p = os.path.join(ART, name)
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def grype_summary(obj):
    if not obj:
        return {"total": 0, "by_sev": {}, "top": []}
    matches = obj.get("matches", [])
    by = {}
    for m in matches:
        sev = (m.get("vulnerability") or {}).get("severity", "Unknown")
        by[sev] = by.get(sev, 0) + 1
    order = {"Critical":0, "High":1, "Medium":2, "Low":3, "Negligible":4, "Unknown":5}
    top = sorted(
        matches,
        key=lambda m: (
            order.get((m.get("vulnerability") or {}).get("severity", "Unknown"), 9),
            ((m.get("vulnerability") or {}).get("fix", {}).get("state") != "not-fixed"),
        ),
    )[:10]

    def row(m):
        v = m.get("vulnerability") or {}
        a = m.get("artifact") or {}
        fix = (v.get("fix") or {}).get("versions") or []
        return {
            "severity": v.get("severity", "Unknown"),
            "id": v.get("id", ""),
            "pkg": a.get("name", ""),
            "ver": a.get("version", ""),
            "fix": ", ".join(fix),
        }

    return {"total": len(matches), "by_sev": by, "top": [row(m) for m in top]}

data = {
    "grype_repo": grype_summary(load("grype.json")),
    "grype_venv": grype_summary(load("grype.venv.json")),
    "semgrep":    {"total": len((load("semgrep.json") or {}).get("results", []))},
    "bandit":     {"total": len((load("bandit.json")  or {}).get("results", []))},
    "gitleaks":   {"total": len((load("gitleaks.json") or {}).get("leaks",   []))
                   if isinstance(load("gitleaks.json"), dict) else 0},
    "trivy":      {"total": sum(len(r.get("Misconfigurations", []))
                   for r in (load("trivy_config.json") or {}).get("Results", []))},
    "generated":  datetime.datetime.now().isoformat(timespec="seconds"),
}

html = f"""<!doctype html><meta charset="utf-8"><title>Security Scan Report</title>
<style>
 body{{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:2rem}}
 h1{{margin-bottom:.25rem}} h2{{margin-top:2rem}}
 table{{border-collapse:collapse;width:100%;margin:.5rem 0 1rem}}
 th,td{{border:1px solid #ddd;padding:.5rem .6rem;font-size:14px}}
 th{{background:#f5f5f5;text-align:left}}
 .muted{{color:#666;font-size:12px}}
 .sev-Critical{{color:#b00020;font-weight:600}}
 .sev-High{{color:#d35400;font-weight:600}}
 .sev-Medium{{color:#c28f0e}} .sev-Low{{color:#357a38}}
 .sev-Negligible,.sev-Unknown{{color:#555}}
</style>
<h1>Security Scan Report</h1>
<div class="muted">Generated: {data['generated']}</div>

<h2>Grype (repo)</h2>
<table><tr><td>Total</td><td>{data['grype_repo']['total']}</td></tr>
<tr><td>By severity</td><td>{', '.join(f"{k}={v}" for k,v in data['grype_repo']['by_sev'].items())}</td></tr></table>

<h2>Grype (venv)</h2>
<table><tr><td>Total</td><td>{data['grype_venv']['total']}</td></tr>
<tr><td>By severity</td><td>{', '.join(f"{k}={v}" for k,v in data['grype_venv']['by_sev'].items())}</td></tr></table>
"""

if data["grype_venv"]["top"]:
    html += "<h3>Top 10 venv vulnerabilities</h3><table><tr><th>Severity</th><th>CVE</th><th>Package</th><th>Version</th><th>Fix Versions</th></tr>"
    for t in data["grype_venv"]["top"]:
        html += f"<tr><td class='sev-{t['severity']}'>{t['severity']}</td><td>{t['id']}</td><td>{t['pkg']}</td><td>{t['ver']}</td><td>{t['fix']}</td></tr>"
    html += "</table>"

html += f"""
<h2>Semgrep</h2><table><tr><td>Total</td><td>{data['semgrep']['total']}</td></tr></table>
<h2>Bandit</h2><table><tr><td>Total</td><td>{data['bandit']['total']}</td></tr></table>
<h2>Gitleaks</h2><table><tr><td>Total</td><td>{data['gitleaks']['total']}</td></tr></table>
<h2>Trivy (IaC/config)</h2><table><tr><td>Total</td><td>{data['trivy']['total']}</td></tr></table>
"""

os.makedirs(ART, exist_ok=True)
with open(os.path.join(ART, "report.html"), "w", encoding="utf-8") as f:
    f.write(html)
print("Wrote run_artifacts/report.html")
