<#
.SYNOPSIS
    One-shot deploy of `lattice-server` to a remote SSH host.

.DESCRIPTION
    Tars the workspace, scps to <Host>, builds via cargo, and starts
    the server with a fresh federation key (or reuses an existing one
    if `LATTICE__FEDERATION_KEY_PATH` already exists on the remote).

    The remote must have rustup (will install if missing), gcc, git.

    Bind addr is 127.0.0.1:<Port> by default — suitable for
    behind-tunnel use. Pass -PublicBind to bind 0.0.0.0 instead.

    Idempotent enough to re-run for upgrades: it transfers fresh
    source, rebuilds, and restarts. Federation keys persist if the
    path is stable across runs.

.EXAMPLE
    .\deploy-node.ps1 -Host pixie -Port 4443
    .\deploy-node.ps1 -Host cnc-server -Port 4443 -KeyPath /tmp/lattice-deploy/fed-b.key
    .\deploy-node.ps1 -Host imac -Port 4443 -RemoteUser matt -PublicBind

.NOTES
    Verified against pixie (Ubuntu 24.04) and cnc-server (openSUSE
    Tumbleweed). See `docs/DEPLOY.md` for the full operations story.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$RemoteHost,
    [int]$Port = 4443,
    [string]$RemoteUser = "",
    [string]$KeyPath = "/tmp/lattice-deploy/federation.key",
    [string]$LogPath = "/tmp/lattice-deploy/lattice-server.log",
    [switch]$PublicBind,
    [switch]$SkipBuild
)

$ErrorActionPreference = "Continue"
$ROOT = (Resolve-Path "$PSScriptRoot\..").Path

$target = if ($RemoteUser) { "$RemoteUser@$RemoteHost" } else { $RemoteHost }
$bindAddr = if ($PublicBind) { "0.0.0.0:$Port" } else { "127.0.0.1:$Port" }

Write-Host ""
Write-Host "==> Deploy target: $target  bind=$bindAddr  key=$KeyPath" -ForegroundColor Magenta

if (-not $SkipBuild) {
    $tarball = "$env:TEMP\lattice.tgz"
    Remove-Item -ErrorAction SilentlyContinue $tarball
    Write-Host "==> Tar workspace" -ForegroundColor Magenta
    Push-Location $ROOT
    try {
        & tar --exclude='./target' --exclude='./scratch' --exclude='./.git' `
            --exclude='./apps/lattice-web/node_modules' `
            --exclude='./apps/lattice-web/dist' `
            -czf $tarball .
        if ($LASTEXITCODE -ne 0) { throw "tar failed" }
    } finally {
        Pop-Location
    }
    Write-Host "    tarball: $((Get-Item $tarball).Length) bytes"

    Write-Host "==> scp tarball to ${target}:~/lattice.tgz" -ForegroundColor Magenta
    & scp $tarball "${target}:~/lattice.tgz"
    if ($LASTEXITCODE -ne 0) { throw "scp failed (exit $LASTEXITCODE)" }

    Write-Host "==> Build on $target (will install rustup if missing)" -ForegroundColor Magenta
    $bootstrap = @'
set -e
if ! command -v cargo >/dev/null && [ ! -x "$HOME/.cargo/bin/cargo" ]; then
    echo "installing rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain stable --profile minimal
fi
source $HOME/.cargo/env 2>/dev/null || true
rm -rf ~/lattice
mkdir ~/lattice
cd ~/lattice
tar xzf ~/lattice.tgz
# sccache-as-RUSTC_WRAPPER is broken on some hosts (seen on
# cnc-server's openSUSE). Bypass.
RUSTC_WRAPPER= CARGO_BUILD_RUSTC_WRAPPER= \
    cargo build --release --bin lattice-server --bin lattice
ls -la target/release/lattice-server target/release/lattice
'@
    & ssh $target $bootstrap
    if ($LASTEXITCODE -ne 0) { throw "remote build failed (exit $LASTEXITCODE)" }
}

Write-Host "==> Start lattice-server on $target" -ForegroundColor Magenta
$keyDir = Split-Path $KeyPath -Parent
$logDir = Split-Path $LogPath -Parent
$startScript = @"
set -e
mkdir -p '$keyDir' '$logDir'
pkill -f lattice-server || true
sleep 1
LATTICE__SERVER__BIND_ADDR='$bindAddr' \
LATTICE__FEDERATION_KEY_PATH='$KeyPath' \
LATTICE__DATABASE_URL='postgres://noop@localhost/noop' \
RUST_LOG=lattice_server=info,axum=warn \
nohup ~/lattice/target/release/lattice-server > '$LogPath' 2>&1 &
echo "PID=`$!"
sleep 2
curl -s 'http://127.0.0.1:$Port/.well-known/lattice/server'
echo ""
"@
& ssh $target $startScript

Write-Host ""
Write-Host "==> Deploy complete" -ForegroundColor Green
Write-Host "    To stop: ssh $target 'pkill -f lattice-server'"
Write-Host "    Logs:    ssh $target 'tail -f $LogPath'"
