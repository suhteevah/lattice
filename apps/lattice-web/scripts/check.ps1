# Quick `cargo check --target wasm32-unknown-unknown` for the Lattice
# web client. Uses the GNU host toolchain — matches the kalshi
# desktop path on this box.

$ErrorActionPreference = 'Stop'

$env:RUSTUP_TOOLCHAIN = 'stable-x86_64-pc-windows-gnu'
if (Test-Path 'C:\msys64\mingw64\bin\gcc.exe') {
    $env:PATH = "C:\msys64\mingw64\bin;$env:PATH"
} else {
    throw 'MinGW gcc not at C:\msys64\mingw64\bin — install MSYS2 mingw64 or switch host toolchain.'
}

$crateDir = Split-Path -Parent $PSScriptRoot
Set-Location $crateDir
& cargo check --target wasm32-unknown-unknown --bin lattice-web @args
