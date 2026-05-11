<#
.SYNOPSIS
    One-shot dev environment bootstrap for the Lattice workspace.

.DESCRIPTION
    Installs / verifies:
      - Rust stable toolchain (rustup, cargo, rustfmt, clippy)
      - wasm32-unknown-unknown target (for lattice-core)
      - cargo-audit, cargo-watch, cargo-nextest
      - Node.js >= 20 (for apps/lattice-web)
      - npm dependencies for apps/lattice-web

    Designed to run from an Administrator PowerShell session. Verbose by
    default — set $env:LATTICE_QUIET = "1" to suppress info messages.

.NOTES
    Author: Matt Gates (suhteevah)
    UAC is assumed disabled per environment policy.
#>

[CmdletBinding()]
param(
    [switch]$SkipNode,
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$Verbose = $env:LATTICE_QUIET -ne "1"

function Write-Step {
    param([string]$Message)
    if ($Verbose) {
        Write-Host ""
        Write-Host "==> $Message" -ForegroundColor Magenta
    }
}

function Write-Info {
    param([string]$Message)
    if ($Verbose) {
        Write-Host "    $Message" -ForegroundColor DarkGray
    }
}

function Test-Command {
    param([string]$Name)
    $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

$ROOT = (Resolve-Path "$PSScriptRoot\..").Path
Write-Step "Lattice dev-setup starting in $ROOT"

# ---------- Rust ----------
Write-Step "Checking Rust toolchain"
if (-not (Test-Command "rustup")) {
    Write-Info "rustup not found, installing..."
    $rustupInit = Join-Path $env:TEMP "rustup-init.exe"
    Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile $rustupInit -UseBasicParsing
    & $rustupInit -y --default-toolchain stable --profile default
    $env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
} else {
    Write-Info "rustup found: $(rustup --version)"
}

Write-Info "Ensuring stable toolchain + rustfmt + clippy"
rustup default stable | Out-Null
rustup component add rustfmt clippy | Out-Null
rustup target add wasm32-unknown-unknown | Out-Null
Write-Info "Rust: $(rustc --version)"
Write-Info "Cargo: $(cargo --version)"

# ---------- Cargo tools ----------
Write-Step "Installing cargo tooling"
foreach ($tool in @("cargo-audit", "cargo-watch", "cargo-nextest")) {
    if (Test-Command $tool -or ((cargo install --list) -match "^$tool ")) {
        if ($Force) {
            Write-Info "$tool already installed (forcing reinstall)"
            cargo install --locked --force $tool
        } else {
            Write-Info "$tool already installed"
        }
    } else {
        Write-Info "Installing $tool"
        cargo install --locked $tool
    }
}

# ---------- Node ----------
if (-not $SkipNode) {
    Write-Step "Checking Node.js"
    if (-not (Test-Command "node")) {
        Write-Warning "Node.js not found. Install Node 20+ from https://nodejs.org/ and re-run."
    } else {
        $nodeVer = node --version
        Write-Info "Node: $nodeVer"
        $major = [int]($nodeVer -replace "^v(\d+)\..*", '$1')
        if ($major -lt 20) {
            Write-Warning "Node $nodeVer is older than 20. Upgrade recommended."
        }
    }

    if (Test-Command "npm") {
        Write-Step "Installing apps/lattice-web npm deps"
        Push-Location (Join-Path $ROOT "apps\lattice-web")
        try {
            npm install
        } finally {
            Pop-Location
        }
    }
}

# ---------- Sanity check ----------
Write-Step "Verifying workspace compiles (cargo check)"
Push-Location $ROOT
try {
    cargo check --workspace 2>&1 | Tee-Object -Variable checkOut | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "cargo check returned non-zero. Output:"
        $checkOut | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkYellow }
    } else {
        Write-Info "cargo check OK"
    }
} finally {
    Pop-Location
}

Write-Step "Done. Next: .\scripts\test-all.ps1"
