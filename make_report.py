import json, os, datetime
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

data = {k: load(v) for k, v in paths.items()}

def grype_summary(obj):
    if not obj: return {"total":0,"by_sev":{},"top":[]}
    matches = obj.get("matches", [])
    by = {}
    for m in matches:
        sev = (m.get("vulnerability") or {}).get("severity","Unknown")
        by[sev] = by.get(sev,0)+1
    order = {"Critical":0,"High":1,"Medium":2,"Low":3,"Negligible":4,"Unknown":5}
    def key(m):
        v = m.get("vulnerability") or {}
        fix = (v.get("fix") or {}).get("state") != "not-fixed"
        return (order.get(v.get("severity","Unknown"), 9), not fix)
    top = sorted(matches, key=key)[:10]
    rows = []
    for m in top:
        v = m.get("vulnerability") or {}
        a = m.get("artifact") or {}
        fixv = (v.get("fix") or {}).get("versions") or []
        rows.append({
            "severity": v.get("severity","Unknown"),
            "id": v.get("id",""),
            "pkg": a.get("name",""),
            "ver": a.get("version",""),
            "fix": ", ".join(fixv),
        })
    return {"total": len(matches), "by_sev": by, "top": rows}

def count_semgrep(obj):
    if not obj: return {"total":0,"by_sev":{}}
    res = obj.get("results", [])
    by = {}
    for r in res:
        by[r.get("severity","")] = by.get(r.get("severity",""),0)+1
    return {"total": len(res), "by_sev": by}

def count_bandit(obj):
    if not obj: return {"total":0,"by_sev":{}}
    res = obj.get("results", [])
    by = {}
    for r in res:
        by[r.get("issue_severity","")] = by.get(r.get("issue_severity",""),0)+1
    return {"total": len(res), "by_sev": by}

def count_gitleaks(obj):
    if not obj: return {"total":0}
    leaks = obj.get("leaks", [])
    return {"total": len(leaks) if isinstance(leaks, list) else 0}

def count_trivy(obj):
    if not obj: return {"total":0}
    if isinstance(obj.get("Results"), list):
        return {"total": sum(len(r.get("Misconfigurations",[])) for r in obj["Results"])}
    return {"total": len(obj.get("Misconfigurations", [])) if "Misconfigurations" in obj else obj.get("Count", 0)}

summary = {
  "generated": datetime.datetime.now().isoformat(timespec="seconds"),
  "grype_repo": grype_summary(data["grype_repo"]),
  "grype_venv": grype_summary(data["grype_venv"]),
  "semgrep":    count_semgrep(data["semgrep"]),
  "bandit":     count_bandit(data["bandit"]),
  "gitleaks":   count_gitleaks(data["gitleaks"]),
  "trivy":      count_trivy(data["trivy_config"]),
}

tpl = Template("""
<!doctype html>
<meta charset="utf-8">
<title>Security Scan Report</title>
<style>
 body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:2rem}
 h1{margin-bottom:.25rem} h2{margin-top:1.5rem}
 table{border-collapse:collapse;width:100%;margin:.5rem 0 1rem}
 th,td{border:1px solid #ddd;padding:.45rem .6rem;font-size:14px}
 th{background:#f5f5f5;text-align:left}
 .muted{color:#666;font-size:12px}
 .sev-Critical{color:#b00020;font-weight:600}
 .sev-High{color:#d35400;font-weight:600}
 .sev-Medium{color:#c28f0e} .sev-Low{color:#357a38}
 .sev-Negligible,.sev-Unknown{color:#555}
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
<tr><th>Severity</th><th>ID</th><th>Package</th><th>Version</th><th>Fix Versions</th></tr>
{% for t in grype_venv.top %}
<tr><td class="sev-{{t.severity}}">{{t.severity}}</td><td>{{t.id}}</td><td>{{t.pkg}}</td><td>{{t.ver}}</td><td>{{t.fix}}</td></tr>
{% endfor %}
</table>
{% endif %}

<h2>Semgrep</h2>
<table><tr><td>Total</td><td>{{ semgrep.total }}</td></tr></table>

<h2>Bandit</h2>
<table><tr><td>Total</td><td>{{ bandit.total }}</td></tr></table>

<h2>Gitleaks</h2>
<table><tr><td>Total</td><td>{{ gitleaks.total }}</td></tr></table>

<h2>Trivy (IaC/config)</h2>
<table><tr><td>Total</td><td>{{ trivy.total }}</td></tr></table>
""")

os.makedirs(ART, exist_ok=True)
open(os.path.join(ART, "report.html"), "w", encoding="utf-8").write(tpl.render(**summary))
print("Wrote run_artifacts/report.html")
