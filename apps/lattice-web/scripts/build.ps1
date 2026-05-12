# Production `trunk build --release` runner for the Lattice web client.
#
# Wrapped so the Tauri 2 `beforeBuildCommand` can invoke it during
# `cargo tauri build`. Uses the GNU host toolchain — same path the
# kalshi-trader-v7 desktop builds on this machine — because it has
# proven to work without MSVC env-loading quirks.

[CmdletBinding()]
param(
    [switch]$NoRelease
)

$ErrorActionPreference = 'Stop'

$env:RUSTUP_TOOLCHAIN = 'stable-x86_64-pc-windows-gnu'

if (Test-Path 'C:\msys64\mingw64\bin\gcc.exe') {
    $env:PATH = "C:\msys64\mingw64\bin;$env:PATH"
} else {
    throw 'MinGW gcc not at C:\msys64\mingw64\bin — install MSYS2 mingw64 or switch host toolchain.'
}

$crateDir = Split-Path -Parent $PSScriptRoot
Set-Location $crateDir

$trunkArgs = @('build')
if (-not $NoRelease) { $trunkArgs += '--release' }

Write-Host "RUSTUP_TOOLCHAIN=$env:RUSTUP_TOOLCHAIN" -ForegroundColor DarkGray
Write-Host "trunk $($trunkArgs -join ' ')  [cwd=$crateDir]" -ForegroundColor Green
# Trunk writes cargo progress to stderr; PowerShell with
# ErrorActionPreference=Stop would misclassify those as errors and
# bail before checking the exit code. Drop the strict mode for the
# trunk invocation itself and rely on $LASTEXITCODE.
$ErrorActionPreference = 'Continue'
& trunk @trunkArgs
exit $LASTEXITCODE
