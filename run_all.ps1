param(
  [string]$RepoPath = ".\samples\demo-repo",
  [string]$VenvSite = ".\.venv\Lib\site-packages"
)

New-Item -ItemType Directory -Force run_artifacts | Out-Null

# Syft SBOMs
syft -q $RepoPath   -o syft-json=run_artifacts\sbom.syft.json
if (Test-Path $VenvSite) {
  syft -q $VenvSite -o syft-json=run_artifacts\sbom.venv.syft.json
}

# Grype scans
grype sbom:run_artifacts\sbom.syft.json -o json | Set-Content -Encoding utf8 run_artifacts\grype.json
if (Test-Path run_artifacts\sbom.venv.syft.json) {
  grype sbom:run_artifacts\sbom.venv.syft.json -o json | Set-Content -Encoding utf8 run_artifacts\grype.venv.json
}

# Quick console summary (safe if files are missing)
$g_repo = 0
$g_venv = 0
if (Test-Path run_artifacts\grype.json) {
  $g_repo = (Get-Content run_artifacts\grype.json -Raw | ConvertFrom-Json).matches.Count
}
if (Test-Path run_artifacts\grype.venv.json) {
  $g_venv = (Get-Content run_artifacts\grype.venv.json -Raw | ConvertFrom-Json).matches.Count
}
"Repo vulns: $g_repo"
"Venv vulns: $g_venv"
