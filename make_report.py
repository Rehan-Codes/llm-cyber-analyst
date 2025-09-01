# make_report.py
import os, json, datetime
from jinja2 import Template

ART = "run_artifacts"
paths = {
    "grype_repo":   os.path.join(ART, "grype.json"),
    "grype_venv":   os.path.join(ART, "grype.venv.json"),
    "semgrep":      os.path.join(ART, "semgrep.json"),
    "bandit":       os.path.join(ART, "bandit.json"),
    "gitleaks":     os.path.join(ART, "gitleaks.json"),
    "trivy_config": os.path.join(ART, "trivy_config.json"),
}

def load(p):
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

data = {k: load(v) for k,v in paths.items()}

def grype_summary(obj):
    if not obj: return {"total":0,"by_sev":{},"top":[]}
    matches = obj.get("matches", [])
    by = {}
    for m in matches:
        sev = (m.get("vulnerability") or {}).get("severity","Unknown")
        by[sev] = by.get(sev,0)+1
    order = {"Critical":0,"High":1,"Medium":2,"Low":3,"Negligible":4,"Unknown":5}
    top = sorted(matches, key=lambda m:(order.get((m.get("vulnerability") or {}).get("severity","Unknown"),9),
                                        ((m.get("vulnerability") or {}).get("fix",{}).get("state")!="not-fixed")))[:10]
    def row(m):
        v = m.get("vulnerability") or {}
        a = m.get("artifact") or {}
        fix = (v.get("fix") or {}).get("versions") or []
        return {
            "severity": v.get("severity","Unknown"),
            "id": v.get("id",""),
            "pkg": a.get("name",""),
            "ver": a.get("version",""),
            "fix": ", ".join(fix)
        }
    return {"total": len(matches), "by_sev": by, "top":[row(m) for m in top]}

def semgrep_summary(obj):
    if not obj: return {"total":0,"by_sev":{}}
    results = obj.get("results", [])
    by = {}
    for r in results:
        sev = r.get("severity","")
        by[sev] = by.get(sev,0)+1
    return {"total": len(results), "by_sev": by}

def bandit_summary(obj):
    if not obj: return {"total":0,"by_sev":{}}
    results = obj.get("results", [])
    by = {}
    for r in results:
        sev = r.get("issue_severity","")
        by[sev] = by.get(sev,0)+1
    return {"total": len(results), "by_sev": by}

def gitleaks_summary(obj):
    # Newer gitleaks writes an array of findings to -r JSON
    try:
        if isinstance(obj, list): return {"total": len(obj)}
        if isinstance(obj, dict) and "leaks" in obj: return {"total": len(obj["leaks"])}
    except Exception:
        pass
    return {"total": 0}

def trivy_summary(obj):
    if not obj: return {"total":0}
    if isinstance(obj, dict) and isinstance(obj.get("Results"), list):
        return {"total": sum(len(r.get("Misconfigurations",[])) for r in obj["Results"])}
    if isinstance(obj, dict) and "Misconfigurations" in obj:
        return {"total": len(obj["Misconfigurations"])}
    return {"total": obj.get("Count", 0) if isinstance(obj, dict) else 0}

summary = {
  "grype_repo": grype_summary(data["grype_repo"]),
  "grype_venv": grype_summary(data["grype_venv"]),
  "semgrep":    semgrep_summary(data["semgrep"]),
  "bandit":     bandit_summary(data["bandit"]),
  "gitleaks":   gitleaks_summary(data["gitleaks"]),
  "trivy":      trivy_summary(data["trivy_config"]),
  "generated":  datetime.datetime.now().isoformat(timespec="seconds"),
}

tpl = Template("""
<!doctype html>
<meta charset="utf-8">
<title>Security Scan Report</title>
<style>
  body { font-family: system-ui, Segoe UI, Arial, sans-serif; margin: 2rem; }
  h1 { margin-bottom: .25rem; }
  h2 { margin-top: 2rem; }
  table { border-collapse: collapse; width: 100%; margin: .5rem 0 1rem; }
  th, td { border: 1px solid #ddd; padding: .5rem .6rem; font-size: 14px; }
  th { background:#f5f5f5; text-align:left; }
  .muted { color:#666; font-size: 12px; }
  .sev-Critical { color:#b00020; font-weight:600; }
  .sev-High     { color:#d35400; font-weight:600; }
  .sev-Medium   { color:#c28f0e; }
  .sev-Low      { color:#357a38; }
  .sev-Negligible,.sev-Unknown { color:#555; }
</style>

<h1>Security Scan Report</h1>
<div class="muted">Generated: {{ generated }}</div>

<h2>Grype (repo)</h2>
<table>
<tr><td>Total</td><td>{{ grype_repo.total }}</td></tr>
<tr><td>By severity</td><td>{% for k,v in grype_repo.by_sev.items() %}{{k}}={{v}}{{ ", " if not loop.last }}{% endfor %}</td></tr>
</table>

<h2>Grype (venv)</h2>
<table>
<tr><td>Total</td><td>{{ grype_venv.total }}</td></tr>
<tr><td>By severity</td><td>{% for k,v in grype_venv.by_sev.items() %}{{k}}={{v}}{{ ", " if not loop.last }}{% endfor %}</td></tr>
</table>

{% if grype_venv.top %}
<h3>Top 10 venv vulnerabilities</h3>
<table>
  <tr><th>Severity</th><th>CVE</th><th>Package</th><th>Version</th><th>Fix Versions</th></tr>
  {% for t in grype_venv.top %}
  <tr>
    <td class="sev-{{t.severity}}">{{ t.severity }}</td>
    <td>{{ t.id }}</td><td>{{ t.pkg }}</td><td>{{ t.ver }}</td><td>{{ t.fix }}</td>
  </tr>
  {% endfor %}
</table>
{% endif %}

<h2>Semgrep</h2><table><tr><td>Total</td><td>{{ semgrep.total }}</td></tr></table>
<h2>Bandit</h2><table><tr><td>Total</td><td>{{ bandit.total }}</td></tr></table>
<h2>Gitleaks</h2><table><tr><td>Total</td><td>{{ gitleaks.total }}</td></tr></table>
<h2>Trivy (IaC/config)</h2><table><tr><td>Total</td><td>{{ trivy.total }}</td></tr></table>
""")

os.makedirs(ART, exist_ok=True)
html = tpl.render(**summary)
with open(os.path.join(ART, "report.html"), "w", encoding="utf-8") as f:
    f.write(html)
print("Wrote run_artifacts/report.html")
