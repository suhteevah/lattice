# Quick `cargo check` for the wasm32 target, inside the VS Build
# Tools env so host-target proc-macros can build. Lighter than a
# full `trunk build` — use it as an inner-loop verification before
# kicking off the full bundle.

$ErrorActionPreference = 'Stop'

$vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
$installPath = & $vswhere -latest -prerelease -products * `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath
$vcvarsBat = Join-Path $installPath 'VC\Auxiliary\Build\vcvars64.bat'
$envDump = cmd.exe /c "`"$vcvarsBat`" && set"
foreach ($line in $envDump) {
    if ($line -match '^([^=]+)=(.*)$') {
        Set-Item -Path "Env:$($Matches[1])" -Value $Matches[2] -ErrorAction SilentlyContinue
    }
}

$crateDir = Split-Path -Parent $PSScriptRoot
Set-Location $crateDir
& cargo check --target wasm32-unknown-unknown --bin lattice-web @args
