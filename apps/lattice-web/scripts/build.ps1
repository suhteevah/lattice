# Production `trunk build --release` runner for the Lattice web client.
#
# Wrapped so the Tauri 2 `beforeBuildCommand` can invoke it during
# `cargo tauri build`. Loads VS Build Tools 2022's developer env so
# host-target proc-macros (serde, getrandom, wasm-bindgen-shared) can
# compile against the MSVC toolchain ahead of trunk's wasm32 build.
#
# Mirrors the env-loading prelude in `scripts/serve.ps1`.

[CmdletBinding()]
param(
    [switch]$NoRelease
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
}

Invoke-VcVars

$crateDir = Split-Path -Parent $PSScriptRoot
Set-Location $crateDir

$trunkArgs = @('build')
if (-not $NoRelease) { $trunkArgs += '--release' }

Write-Host "trunk $($trunkArgs -join ' ')  [cwd=$crateDir]"
& trunk @trunkArgs
