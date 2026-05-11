# Run a local `lattice-server` for browser-client dev. Binds to
# 127.0.0.1:8080 (matches `DEFAULT_SERVER_URL` in
# `apps/lattice-web/src/app.rs`). Uses a per-run scratch directory
# under `J:\lattice\.run` for federation key + state snapshot — both
# gitignored.

[CmdletBinding()]
param(
    [string]$BindAddr = '127.0.0.1:8080'
)

$ErrorActionPreference = 'Stop'

$runDir = 'J:\lattice\.run\dev-server'
if (-not (Test-Path $runDir)) {
    New-Item -ItemType Directory -Path $runDir -Force | Out-Null
}

$env:LATTICE__SERVER__BIND_ADDR = $BindAddr
$env:LATTICE__FEDERATION_KEY_PATH = Join-Path $runDir 'federation.key'
$env:LATTICE__SNAPSHOT_PATH = Join-Path $runDir 'snapshot.json'
$env:LATTICE__ENVIRONMENT = 'development'
$env:RUST_LOG = 'lattice_server=debug,info'

# Disable Postgres — the in-memory ServerState is fine for the
# browser-client smoke test. (Server still tries to connect at startup
# only if configured; defaults are tolerant.)
$env:LATTICE__DATABASE_URL = 'postgres://disabled:disabled@localhost:5432/disabled'

Write-Host "starting lattice-server on $BindAddr (run dir: $runDir)"
$bin = 'J:\lattice\target\debug\lattice-server.exe'
if (-not (Test-Path $bin)) {
    throw "lattice-server.exe not built. Run scripts/check-server.ps1 build -p lattice-server"
}
& $bin
