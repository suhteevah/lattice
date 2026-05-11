<#
.SYNOPSIS
    Build the lattice-core WASM module and produce
    `apps/lattice-web/src/wasm/lattice_core{_bg.wasm,.js,.d.ts}`.

.DESCRIPTION
    Runs `cargo build --target wasm32-unknown-unknown` on lattice-core
    then `wasm-bindgen --target web` to generate the JS glue. The
    `--target web` output is consumed by Vite's dynamic-import in
    `App.tsx`.

    Native Windows builds of `wasm-bindgen-cli` are broken on the
    project's MinGW toolchain (icu/winapi build scripts), so this
    script invokes the WSL-installed `wasm-bindgen` binary for the
    binding step. The .wasm itself is produced by the Windows host's
    cargo build.

.NOTES
    Requires: WSL `wasm-bindgen` at /home/sati/.cargo/bin/wasm-bindgen
    (cargo install wasm-bindgen-cli inside WSL).
#>

[CmdletBinding()]
param(
    [switch]$Debug
)

$ErrorActionPreference = "Continue"
$ROOT = (Resolve-Path "$PSScriptRoot\..\..\..").Path
$OUT = (Resolve-Path "$PSScriptRoot\..").Path
. "$ROOT\scripts\env-setup.ps1"

$profile = if ($Debug) { "" } else { "--release" }
$buildDir = if ($Debug) { "debug" } else { "release" }

Write-Host "==> cargo build --target wasm32-unknown-unknown" -ForegroundColor Magenta
Push-Location $ROOT
try {
    $cargoArgs = @(
        "build", "--target", "wasm32-unknown-unknown",
        "-p", "lattice-core", "--features", "lattice-crypto/wasm"
    )
    if (-not $Debug) { $cargoArgs += "--release" }
    $cargo = Start-Process -FilePath "cargo" -ArgumentList $cargoArgs `
        -NoNewWindow -Wait -PassThru
    if ($cargo.ExitCode -ne 0) { throw "cargo build failed ($($cargo.ExitCode))" }
} finally {
    Pop-Location
}

$wasm = Join-Path $ROOT "target\wasm32-unknown-unknown\$buildDir\lattice_core.wasm"
if (-not (Test-Path $wasm)) {
    Write-Host "wasm artifact not found at $wasm" -ForegroundColor Red
    exit 1
}
$wasmSize = (Get-Item $wasm).Length
Write-Host "    .wasm: $($wasmSize) bytes"

Write-Host "==> wasm-bindgen --target web (via WSL)" -ForegroundColor Magenta
$outDir = Join-Path $OUT "src\wasm"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
# Convert Windows paths to /mnt/* for WSL.
$wsl_wasm = "/mnt/" + $wasm.Substring(0, 1).ToLower() + ($wasm.Substring(2) -replace '\\', '/')
$wsl_out  = "/mnt/" + $outDir.Substring(0, 1).ToLower() + ($outDir.Substring(2) -replace '\\', '/')
$bindgen = wsl -d Ubuntu -- bash -lc "wasm-bindgen --target web --out-dir '$wsl_out' '$wsl_wasm' 2>&1"
$bindgen
if ($LASTEXITCODE -ne 0) {
    Write-Host "wasm-bindgen failed" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "==> WASM bundle ready" -ForegroundColor Green
Get-ChildItem $outDir | Select-Object Name, Length | Format-Table -AutoSize
