# deploy.ps1 — Build SSE UAR Dashboard and publish
# Primary: gecgithub01.walmart.com/lparise/sse-uar-dashboard  (enterprise)
# Mirror:  github.com/leonardoparisella-sudo/sse-uar-dashboard (GitHub Pages)
#
# Usage: .\deploy.ps1 [-version "v1.1"]
# Requires: Python 3.13, git, authenticated Google ADC

param(
    [string]$version = ""   # Optional: tag this deploy (e.g. -version "v1.1")
)

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

# ── Guard: must be on master ──────────────────────────────────────────────────
Set-Location $REPO_DIR
$branch = git rev-parse --abbrev-ref HEAD 2>&1
if ($branch -ne "master") {
    Write-Host "ERROR: You are on branch '$branch', not master." -ForegroundColor Red
    Write-Host "  To deploy: git checkout master; git merge dev" -ForegroundColor Yellow
    exit 1
}
Write-Host "   Branch: master ✓" -ForegroundColor Green

# ── Step 1: Build ─────────────────────────────────────────────────────────────
Write-Host "[1/5] Running build_dashboard.py..." -ForegroundColor Yellow
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

# ── Step 2: Copy as index.html ────────────────────────────────────────────────
Write-Host "[2/5] Copying to index.html..." -ForegroundColor Yellow
Copy-Item -Path $HTML_OUT -Destination $INDEX -Force
Write-Host "   OK: index.html updated" -ForegroundColor Green

# ── Step 3: Git commit ────────────────────────────────────────────────────────
Write-Host "[3/5] Committing..." -ForegroundColor Yellow
git add sse_uar_dashboard.html index.html
$timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm") + " CT"
$versionLabel = if ($version) { " [$version]" } else { "" }
$msg = "chore: refresh dashboard$versionLabel $timestamp`n`n🌀 Magic applied with Wibey CLI 🪄 (https://wibey.walmart.com/cli)"
git commit -m $msg
if ($LASTEXITCODE -ne 0) {
    Write-Host "   Nothing to commit (dashboard unchanged)." -ForegroundColor Gray
}

# ── Step 4: Version tag (optional) ────────────────────────────────────────────
if ($version) {
    Write-Host "[4/5] Tagging $version..." -ForegroundColor Yellow
    git tag -a $version -m "Release $version — $timestamp" 2>&1
    git push ghe $version 2>&1
    $env:no_proxy = "github.com"; $env:NO_PROXY = "github.com"
    git -c http.proxy="" -c https.proxy="" push origin $version 2>&1
    Write-Host "   Tagged: $version" -ForegroundColor Green
} else {
    Write-Host "[4/5] Skipping version tag (use -version 'v1.x' to tag)" -ForegroundColor Gray
}

# ── Step 5: Push to both remotes ──────────────────────────────────────────────
Write-Host "[5/5] Pushing to Walmart GHE (primary)..." -ForegroundColor Yellow
git push ghe master
if ($LASTEXITCODE -ne 0) {
    Write-Host "GHE PUSH FAILED." -ForegroundColor Red
    exit 1
}
Write-Host "   OK: gecgithub01.walmart.com/lparise/sse-uar-dashboard" -ForegroundColor Green

Write-Host "      Mirroring to github.com (GitHub Pages)..." -ForegroundColor Gray
$env:no_proxy = "github.com"; $env:NO_PROXY = "github.com"
git -c http.proxy="" -c https.proxy="" push origin master 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "   OK: github.com mirror updated" -ForegroundColor Green
} else {
    Write-Host "   WARN: github.com mirror push failed (non-fatal)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " DEPLOYED!" -ForegroundColor Green
Write-Host " Enterprise: https://gecgithub01.walmart.com/lparise/sse-uar-dashboard" -ForegroundColor Cyan
Write-Host " Pages:      https://leonardoparisella-sudo.github.io/sse-uar-dashboard/" -ForegroundColor Cyan
if ($version) { Write-Host " Version:    $version" -ForegroundColor Cyan }
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
