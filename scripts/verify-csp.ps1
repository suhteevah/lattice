<#
.SYNOPSIS
    Verify the lattice-web production CSP + SRI assets after a `trunk build`.

.DESCRIPTION
    Replaces the old Node-based verify-csp.mjs (which was tied to the
    pre-2026-05 Vite/Solid build). This rewritten verifier:

      1. Parses `apps/lattice-web/csp.json` and rebuilds the
         Content-Security-Policy string.
      2. Sanity-checks the policy for disallowed tokens
         (`'unsafe-eval'`, `'unsafe-inline'` in script-src, wildcard
         origins outside `data:` / `blob:`).
      3. If `apps/lattice-web/dist/` exists (i.e. the user ran
         `trunk build`), confirms that the generated `index.html`
         references at least one wasm asset and that every `<link
         rel="modulepreload" ... integrity=...>` SHA-384 hash matches
         the actual file content under dist/.

    Exits non-zero on any inconsistency. Production deploys gate on
    this script.

.PARAMETER SkipBuildCheck
    Skip the SRI hash sweep over dist/. Useful when running this in
    a fresh clone before the first `trunk build`.
#>

[CmdletBinding()]
param(
    [switch]$SkipBuildCheck
)

$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path "$PSScriptRoot\..").Path
$webRoot = Join-Path $repoRoot 'apps\lattice-web'
$cspPath = Join-Path $webRoot 'csp.json'
$distDir = Join-Path $webRoot 'dist'

if (-not (Test-Path $cspPath)) {
    Write-Error "csp.json not found at $cspPath"
    exit 2
}

Write-Host "==> verify-csp" -ForegroundColor Magenta
$cspDoc = Get-Content $cspPath -Raw | ConvertFrom-Json

# --- 1. Build the policy string and dump it.
$directiveParts = @()
foreach ($key in ($cspDoc.directives | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name)) {
    $values = $cspDoc.directives.$key
    $directiveParts += "$key $($values -join ' ')"
}
$cspString = $directiveParts -join '; '
Write-Host "Content-Security-Policy:" -ForegroundColor DarkGray
Write-Host "  $cspString" -ForegroundColor DarkGray

# --- 2. Disallowed tokens.
$failures = @()
$scriptSrc = ($cspDoc.directives.'script-src') -join ' '
if ($scriptSrc -match "'unsafe-eval'") {
    $failures += "script-src contains 'unsafe-eval'"
}
if ($scriptSrc -match "'unsafe-inline'") {
    $failures += "script-src contains 'unsafe-inline'"
}
foreach ($d in 'default-src','script-src','style-src','connect-src','img-src','font-src','object-src','base-uri','frame-ancestors','form-action') {
    $vals = $cspDoc.directives.$d
    if (-not $vals) { continue }
    foreach ($v in $vals) {
        if ($v -eq '*') {
            $failures += "$d contains wildcard '*'"
        }
    }
}

# --- 3. SRI sweep over dist/ if it exists.
$sriChecked = 0
if (-not $SkipBuildCheck -and (Test-Path $distDir)) {
    $indexHtml = Join-Path $distDir 'index.html'
    if (-not (Test-Path $indexHtml)) {
        $failures += 'dist/index.html missing — re-run trunk build'
    } else {
        $html = Get-Content $indexHtml -Raw
        if ($html -notmatch '\.wasm') {
            $failures += "dist/index.html does not reference any .wasm asset"
        }

        # Walk every integrity="sha384-..." attribute and verify the hash
        # matches the dist/ file referenced in the same tag.
        $sriRegex = [regex]'<link[^>]*?\bhref="([^"]+)"[^>]*?\bintegrity="sha384-([^"]+)"'
        foreach ($m in $sriRegex.Matches($html)) {
            $href = $m.Groups[1].Value
            $expectedB64 = $m.Groups[2].Value
            # Resolve href under dist/.
            $relPath = $href.TrimStart('/').Replace('/', '\')
            $assetPath = Join-Path $distDir $relPath
            if (-not (Test-Path $assetPath)) {
                $failures += "SRI references missing asset: $href"
                continue
            }
            $bytes = [System.IO.File]::ReadAllBytes($assetPath)
            $sha384 = [System.Security.Cryptography.SHA384]::Create()
            $hash = $sha384.ComputeHash($bytes)
            $actualB64 = [Convert]::ToBase64String($hash)
            if ($actualB64 -ne $expectedB64) {
                $failures += "SRI mismatch on $href (expected sha384-$expectedB64, got sha384-$actualB64)"
            } else {
                $sriChecked++
            }
        }
    }
}

# --- 4. Report.
if ($failures.Count -gt 0) {
    Write-Host ""
    Write-Host "FAILURES:" -ForegroundColor Red
    foreach ($f in $failures) {
        Write-Host "  - $f" -ForegroundColor Red
    }
    exit 1
}

Write-Host ""
Write-Host "ok" -ForegroundColor Green
if ($sriChecked -gt 0) {
    Write-Host "  $sriChecked SRI hash(es) verified" -ForegroundColor DarkGreen
} elseif (-not $SkipBuildCheck -and -not (Test-Path $distDir)) {
    Write-Host '  (no dist/ — run trunk build to enable SRI sweep)' -ForegroundColor DarkYellow
}
exit 0
