<#
.SYNOPSIS
    Per-session environment setup for the Lattice workspace.

.DESCRIPTION
    Dot-source this before running cargo if your machine has the GNU host
    toolchain installed but rustup's default host is MSVC and you do not
    have Visual Studio Build Tools. This sets RUSTUP_TOOLCHAIN to force
    the GNU host (uses MinGW gcc as the linker — which must be on PATH).

    On a machine with MSVC Build Tools installed, this script is a no-op
    you can safely run anyway.

.EXAMPLE
    . .\scripts\env-setup.ps1
    cargo check --workspace

.NOTES
    Author: Matt Gates (suhteevah)
#>

# Only override if MSVC linker is unavailable.
$msvcLink = Get-Command link.exe -ErrorAction SilentlyContinue
if ($msvcLink -and $msvcLink.Source -like "*Microsoft Visual Studio*") {
    Write-Host "MSVC link.exe found at $($msvcLink.Source); using MSVC host." -ForegroundColor DarkGray
    return
}

$gccPath = Get-Command gcc -ErrorAction SilentlyContinue
if (-not $gccPath) {
    Write-Warning "Neither MSVC link.exe nor gcc found on PATH. Install one of: VS Build Tools (MSVC) or MSYS2 mingw64 (GNU)."
    return
}

$env:RUSTUP_TOOLCHAIN = "stable-x86_64-pc-windows-gnu"
Write-Host "Using GNU host toolchain (gcc at $($gccPath.Source))" -ForegroundColor DarkGray
