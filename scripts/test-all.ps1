<#
.SYNOPSIS
    Full pre-commit / pre-push gate for the Lattice workspace.

.DESCRIPTION
    Runs (fail-fast):
      1. cargo fmt --all -- --check
      2. cargo clippy --workspace --all-targets -- -D warnings
      3. cargo nextest run --workspace  (or `cargo test --workspace`)
      4. cargo check -p lattice-core --target wasm32-unknown-unknown
      5. cargo audit
      6. apps/lattice-web: npm run typecheck && npm run verify-csp

    Verbose by default.
#>

[CmdletBinding()]
param(
    [switch]$SkipWasm,
    [switch]$SkipWeb,
    [switch]$SkipAudit
)

$ErrorActionPreference = "Stop"
$ROOT = (Resolve-Path "$PSScriptRoot\..").Path
Push-Location $ROOT

$failures = @()

function Invoke-Step {
    param(
        [string]$Name,
        [scriptblock]$Action
    )
    Write-Host ""
    Write-Host "==> $Name" -ForegroundColor Magenta
    $start = Get-Date
    try {
        & $Action
        if ($LASTEXITCODE -ne 0) {
            $script:failures += $Name
            Write-Host "    FAIL ($Name) exit=$LASTEXITCODE" -ForegroundColor Red
        } else {
            $elapsed = (New-TimeSpan $start (Get-Date)).TotalSeconds
            Write-Host ("    OK  ({0:F1}s)" -f $elapsed) -ForegroundColor Green
        }
    } catch {
        $script:failures += $Name
        Write-Host "    EXCEPTION ($Name): $_" -ForegroundColor Red
    }
}

try {
    Invoke-Step "cargo fmt --check" {
        cargo fmt --all -- --check
    }

    Invoke-Step "cargo clippy" {
        cargo clippy --workspace --all-targets --all-features -- -D warnings
    }

    Invoke-Step "cargo test (workspace)" {
        if (Get-Command cargo-nextest -ErrorAction SilentlyContinue) {
            cargo nextest run --workspace --all-features
        } else {
            cargo test --workspace --all-features
        }
    }

    if (-not $SkipWasm) {
        Invoke-Step "cargo check wasm32 (lattice-core)" {
            cargo check -p lattice-core --target wasm32-unknown-unknown --features lattice-crypto/wasm
        }
    }

    if (-not $SkipAudit) {
        Invoke-Step "cargo audit" {
            cargo audit
        }
    }

    if (-not $SkipWeb) {
        Push-Location "apps\lattice-web"
        try {
            Invoke-Step "lattice-web typecheck" {
                npm run typecheck
            }
            Invoke-Step "lattice-web verify-csp" {
                npm run verify-csp
            }
        } finally {
            Pop-Location
        }
    }
} finally {
    Pop-Location
}

Write-Host ""
if ($failures.Count -gt 0) {
    Write-Host "FAILED steps:" -ForegroundColor Red
    foreach ($f in $failures) { Write-Host "  - $f" -ForegroundColor Red }
    exit 1
} else {
    Write-Host "All checks green." -ForegroundColor Green
    exit 0
}
