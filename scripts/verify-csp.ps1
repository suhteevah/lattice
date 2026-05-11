<#
.SYNOPSIS
    Thin PowerShell wrapper around apps/lattice-web/scripts/verify-csp.mjs.

.DESCRIPTION
    Runs the Node-based CSP consistency check from anywhere in the repo.
    Exits non-zero if the CSP, vite.config.ts, and index.html meta tag
    disagree, or if any policy contains a disallowed token.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$ROOT = (Resolve-Path "$PSScriptRoot\..").Path
$WEB  = Join-Path $ROOT "apps\lattice-web"

if (-not (Test-Path $WEB)) {
    Write-Error "apps/lattice-web not found at $WEB"
    exit 2
}

Push-Location $WEB
try {
    Write-Host "==> verify-csp" -ForegroundColor Magenta
    node scripts/verify-csp.mjs
    exit $LASTEXITCODE
} finally {
    Pop-Location
}
