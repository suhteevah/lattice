# Tauri dev runner for the Lattice desktop shell.
#
# Layered on top of the GNU toolchain (same path the kalshi-trader-v7
# desktop builds on this box; MinGW windres is required for the
# Windows resource compilation step that bakes the icon into the EXE).
# MSVC also works but isn't required — `cargo tauri dev` opens the
# WebView pointed at the trunk-serve frontend specified in
# `tauri.conf.json` (`beforeDevCommand`).

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# Pin GNU host for proc-macros (matches what the rest of the workspace
# builds against on this machine).
$env:RUSTUP_TOOLCHAIN = 'stable-x86_64-pc-windows-gnu'

# Add MinGW so `windres` is on PATH for tauri-build's resource step.
if (Test-Path 'C:\msys64\mingw64\bin\windres.exe') {
    $env:PATH = "C:\msys64\mingw64\bin;$env:PATH"
} else {
    Write-Warning 'MinGW windres not at C:\msys64\mingw64\bin — tauri-build may fail on the Windows resource step.'
}

$crateDir = Split-Path -Parent $PSScriptRoot
Set-Location $crateDir

Write-Host "RUSTUP_TOOLCHAIN=$env:RUSTUP_TOOLCHAIN" -ForegroundColor DarkGray
Write-Host "windres -> $((Get-Command windres -ErrorAction SilentlyContinue).Source)" -ForegroundColor DarkGray
Write-Host "cargo tauri dev  [cwd=$crateDir]" -ForegroundColor Green
# cargo writes progress to stderr; relax strict mode for native exe.
$ErrorActionPreference = 'Continue'
& cargo tauri dev
exit $LASTEXITCODE
