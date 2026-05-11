# Dev-serve helper that boots `trunk serve` inside the Visual Studio
# 2022 developer environment so MSVC `link.exe` is on PATH ahead of
# Git's stub `link.exe`. Without this, build scripts (proc-macros and
# `getrandom`, `serde`, `wasm-bindgen-shared`, etc.) fail to compile
# for the host triple `x86_64-pc-windows-msvc` even though the final
# crate target is `wasm32-unknown-unknown`.
#
# We resolve the install via `vswhere.exe` rather than trusting
# `Launch-VsDevShell.ps1`, because the latter occasionally fails to
# locate `vswhere` when invoked from a non-interactive child shell.
#
# Usage:
#   pwsh -ExecutionPolicy Bypass -File scripts/serve.ps1

[CmdletBinding()]
param(
    [switch]$NoAutoReload
)

$ErrorActionPreference = 'Stop'

function Invoke-VcVars {
    $vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path $vswhere)) {
        throw "vswhere.exe not found at $vswhere"
    }

    $installPath = & $vswhere `
        -latest -prerelease -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath
    if (-not $installPath) {
        throw 'vswhere returned no VC++ Tools install. Install "Build Tools for Visual Studio" with the C++ workload.'
    }

    $vcvarsBat = Join-Path $installPath 'VC\Auxiliary\Build\vcvars64.bat'
    if (-not (Test-Path $vcvarsBat)) {
        throw "vcvars64.bat not found at $vcvarsBat"
    }

    # `vcvars64.bat && set` dumps the resulting env. We diff it into
    # the current PowerShell process so trunk's child processes get
    # MSVC PATH / INCLUDE / LIB / LIBPATH set correctly.
    $vcCmd = '"' + $vcvarsBat + '" && set'
    $envDump = cmd.exe /c $vcCmd
    foreach ($line in $envDump) {
        if ($line -match '^([^=]+)=(.*)$') {
            Set-Item -Path "Env:$($Matches[1])" -Value $Matches[2] -ErrorAction SilentlyContinue
        }
    }

    $link = Get-Command link.exe -ErrorAction SilentlyContinue
    if (-not $link -or $link.Source -notlike '*VC\Tools\MSVC*') {
        throw "MSVC link.exe still not resolved (got '$($link.Source)'). vcvars64.bat may have failed."
    }
    Write-Host "VC++ env loaded ($installPath)"
    Write-Host "link.exe -> $($link.Source)"
}

Invoke-VcVars

$crateDir = Split-Path -Parent $PSScriptRoot
Set-Location $crateDir

$trunkArgs = @('serve')
if ($NoAutoReload) { $trunkArgs += '--no-autoreload' }

Write-Host "trunk $($trunkArgs -join ' ')  [cwd=$crateDir]"
& trunk @trunkArgs
