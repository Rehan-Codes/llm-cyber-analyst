#!/usr/bin/env python3
import os, json, datetime

ART = "run_artifacts"
os.makedirs(ART, exist_ok=True)

def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def grype_summary(obj):
    if not obj: return {"total": 0, "by_sev": {}, "top": []}
    matches = obj.get("matches", [])
    by = {}
    for m in matches:
        sev = (m.get("vulnerability") or {}).get("severity", "Unknown")
        by[sev] = by.get(sev, 0) + 1
    order = {"Critical":0,"High":1,"Medium":2,"Low":3,"Negligible":4,"Unknown":5}
    top = sorted(
        matches,
        key=lambda m: (
            order.get((m.get("vulnerability") or {}).get("severity","Unknown"), 9),
            ((m.get("vulnerability") or {}).get("fix",{}).get("state") != "not-fixed"),
        ),
    )[:10]

    def row(m):
        v = m.get("vulnerability") or {}
        a = m.get("artifact") or {}
        fix = (v.get("fix") or {}).get("versions") or []
        return {
            "severity": v.get("severity","Unknown"),
            "id": v.get("id",""),
            "pkg": a.get("name",""),
            "ver": a.get("version",""),
            "fix": ", ".join(fix),
        }

    return {"total": len(matches), "by_sev": by, "top": [row(m) for m in top]}

def simple_count(obj, outer="results", inner_key=None):
    if not obj: return {"total": 0}
    if inner_key:  # trivy config format
        # trivy can be {Results:[{Misconfigurations:[...]}]} or flat
        if isinstance(obj.get("Results"), list):
            total = sum(len(r.get(inner_key, [])) for r in obj["Results"])
        else:
            total = len(obj.get(inner_key, []))
        return {"total": total}
    # semgrep/bandit simple results list
    return {"total": len(obj.get(outer, []))}

# Load artifacts produced earlier in the job
data = {
    "grype_repo":   load_json(os.path.join(ART, "grype.json")),
    "grype_venv":   load_json(os.path.join(ART, "grype.venv.json")),
    "semgrep":      load_json(os.path.join(ART, "semgrep.json")),
    "bandit":       load_json(os.path.join(ART, "bandit.json")),
    "gitleaks":     load_json(os.path.join(ART, "gitleaks.json")),
    "trivy_config": load_json(os.path.join(ART, "trivy_config.json")),
}

summ = {
    "generated": datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z",
    "grype_repo": grype_summary(data["grype_repo"]),
    "grype_venv": grype_summary(data["grype_venv"]),
    "semgrep":    simple_count(data["semgrep"], outer="results"),
    "bandit":     simple_count(data["bandit"], outer="results"),
    "gitleaks":   {"total": len((data["gitleaks"] or {}).get("leaks", [])) if isinstance(data["gitleaks"], dict) else 0},
    "trivy":      simple_count(data["trivy_config"], inner_key="Misconfigurations"),
}

def sev_chip(s): return f'<span class="sev sev-{s}">{s}</span>'

def render_table(rows):
    if not rows: return ""
    out = ['<table><tr><th>Severity</th><th>CVE</th><th>Package</th><th>Version</th><th>Fix Versions</th></tr>']
    for r in rows:
        out.append(
            f"<tr><td>{sev_chip(r['severity'])}</td><td>{r['id']}</td>"
            f"<td>{r['pkg']}</td><td>{r['ver']}</td><td>{r['fix']}</td></tr>"
        )
    out.append("</table>")
    return "\n".join(out)

def by_sev_str(d):
    if not d: return "—"
    return ", ".join(f"{k}={v}" for k, v in d.items())

html = f"""<!doctype html>
<meta charset="utf-8">
<title>Security Scan Report</title>
<style>
  body{{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:2rem}}
  h1{{margin-bottom:.25rem}} h2{{margin-top:1.5rem}}
  table{{border-collapse:collapse;width:100%;margin:.25rem 0 1rem}}
  th,td{{border:1px solid #ddd;padding:.5rem .6rem;font-size:14px}}
  th{{background:#f5f5f5;text-align:left}}
  .muted{{color:#666;font-size:12px}}
  .sev{{padding:.1rem .35rem;border-radius:.4rem;background:#eee}}
  .sev-Critical{{background:#ffd6d6;color:#a40000;font-weight:600}}
  .sev-High{{background:#ffe4cc;color:#9a3d00;font-weight:600}}
  .sev-Medium{{background:#fff2cc;color:#7a5d00}}
  .sev-Low{{background:#e6f4ea;color:#205a2f}}
</style>

<h1>Security Scan Report</h1>
<div class="muted">Generated: {summ['generated']}</div>

<h2>Grype (repo)</h2>
<table>
  <tr><td>Total</td><td>{summ['grype_repo']['total']}</td></tr>
  <tr><td>By severity</td><td>{by_sev_str(summ['grype_repo']['by_sev'])}</td></tr>
</table>

<h2>Grype (venv)</h2>
<table>
  <tr><td>Total</td><td>{summ['grype_venv']['total']}</td></tr>
  <tr><td>By severity</td><td>{by_sev_str(summ['grype_venv']['by_sev'])}</td></tr>
</table>
<h3>Top 10 venv vulnerabilities</h3>
{render_table(summ['grype_venv']['top'])}

<h2>Semgrep</h2>
<table><tr><td>Total</td><td>{summ['semgrep']['total']}</td></tr></table>

<h2>Bandit</h2>
<table><tr><td>Total</td><td>{summ['bandit']['total']}</td></tr></table>

<h2>Gitleaks</h2>
<table><tr><td>Total</td><td>{summ['gitleaks']['total']}</td></tr></table>

<h2>Trivy (IaC/config)</h2>
<table><tr><td>Total</td><td>{summ['trivy']['total']}</td></tr></table>
"""

out = os.path.join(ART, "report.html")
with open(out, "w", encoding="utf-8") as f:
    f.write(html)
print(f"Wrote {out}")
