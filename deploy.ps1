# deploy.ps1 — Build SSE UAR Dashboard and publish to GitHub Pages
# Usage: .\deploy.ps1
# Requires: Python 3.13, git, authenticated Google ADC (gcloud auth application-default login)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$REPO_DIR = $PSScriptRoot
$HTML_OUT = Join-Path $REPO_DIR "sse_uar_dashboard.html"
$INDEX    = Join-Path $REPO_DIR "index.html"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " SSE UAR Dashboard — Build & Deploy" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ── Step 1: Build ─────────────────────────────────────────────────────────────
Write-Host "[1/4] Running build_dashboard.py..." -ForegroundColor Yellow
Set-Location $REPO_DIR
py -3.13 build_dashboard.py
if ($LASTEXITCODE -ne 0) {
    Write-Host "BUILD FAILED. Aborting deploy." -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $HTML_OUT)) {
    Write-Host "ERROR: sse_uar_dashboard.html not found after build." -ForegroundColor Red
    exit 1
}

$sizeMB = [math]::Round((Get-Item $HTML_OUT).Length / 1MB, 1)
Write-Host "   Built: sse_uar_dashboard.html ($sizeMB MB)" -ForegroundColor Green

# ── Step 2: Copy as index.html (GitHub Pages serves index.html by default) ───
Write-Host "[2/4] Copying to index.html..." -ForegroundColor Yellow
Copy-Item -Path $HTML_OUT -Destination $INDEX -Force
Write-Host "   OK: index.html updated" -ForegroundColor Green

# ── Step 3: Git commit ────────────────────────────────────────────────────────
Write-Host "[3/4] Committing to git..." -ForegroundColor Yellow
Set-Location $REPO_DIR
git add sse_uar_dashboard.html index.html
$timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm") + " CT"
$msg = "chore: refresh dashboard $timestamp`n`n🌀 Magic applied with Wibey CLI 🪄 (https://wibey.walmart.com/cli)"
git commit -m $msg
if ($LASTEXITCODE -ne 0) {
    Write-Host "   Nothing to commit (dashboard unchanged)." -ForegroundColor Gray
}

# ── Step 4: Push ──────────────────────────────────────────────────────────────
Write-Host "[4/4] Pushing to GitHub..." -ForegroundColor Yellow
$env:no_proxy = "github.com"
$env:NO_PROXY  = "github.com"
git -c http.proxy="" -c https.proxy="" push origin master
if ($LASTEXITCODE -ne 0) {
    Write-Host "PUSH FAILED. Check your network / token." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " DEPLOYED! Dashboard live at:" -ForegroundColor Green
Write-Host " https://leonardoparisella-sudo.github.io/sse-uar-dashboard/" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
