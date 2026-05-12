# Dev-serve helper that boots `trunk serve` against the GNU host
# toolchain. Matches the kalshi-trader-v7 desktop build path on this
# box; MSVC is also installed but the GNU path is simpler and avoids
# vcvars64 env-loading quirks.

[CmdletBinding()]
param(
    [switch]$NoAutoReload
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

$trunkArgs = @('serve')
if ($NoAutoReload) { $trunkArgs += '--no-autoreload' }

Write-Host "RUSTUP_TOOLCHAIN=$env:RUSTUP_TOOLCHAIN" -ForegroundColor DarkGray
Write-Host "trunk $($trunkArgs -join ' ')  [cwd=$crateDir]" -ForegroundColor Green
# Trunk emits cargo progress to stderr; relax strict mode so
# PowerShell doesn't bail before checking the exit code.
$ErrorActionPreference = 'Continue'
& trunk @trunkArgs
exit $LASTEXITCODE
