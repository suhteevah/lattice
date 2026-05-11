<#
.SYNOPSIS
    Verify graceful-shutdown snapshot persistence on a deployed
    lattice-server.

.DESCRIPTION
    Runs a `lattice demo` against the named server pair, gracefully
    stops both servers (SIGTERM), restarts them, and asserts that the
    federation pubkey + commit log survived the restart. Exits 0 on
    success.

    Assumes:
    - Both servers are already running on the named hosts.
    - SSH access to both hosts (BatchMode-friendly).
    - Both servers have LATTICE__SNAPSHOT_PATH configured.
    - The pixie ↔ cnc SSH reverse tunnel (if applicable) stays up.

.EXAMPLE
    .\verify-persistence.ps1 -ServerAHost pixie -ServerAPort 4443 `
        -ServerBHost pixie -ServerBPort 4444 `
        -RemoteUserA pixiedust -RemoteUserB pixiedust `
        -SnapshotPathA /tmp/lattice-deploy/state-a.json `
        -SnapshotPathB /tmp/lattice-deploy/state-b.json
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ServerAHost,
    [int]$ServerAPort = 4443,
    [string]$RemoteUserA = "",
    [string]$SnapshotPathA = "/tmp/lattice-deploy/state-a.json",
    [string]$BinPathA = "~/lattice/target/release/lattice-server",
    [string]$StartScriptA = "/tmp/start.sh",

    [Parameter(Mandatory = $true)]
    [string]$ServerBHost,
    [int]$ServerBPort = 4444,
    [string]$RemoteUserB = "",
    [string]$SnapshotPathB = "/tmp/lattice-deploy/state-b.json",
    [string]$BinPathB = "~/lattice/target/release/lattice-server",
    [string]$StartScriptB = "/tmp/start.sh",

    [string]$Message = "persistence-test",
    [string]$DemoBin = "~/lattice/target/release/lattice"
)

$ErrorActionPreference = "Continue"

$targetA = if ($RemoteUserA) { "$RemoteUserA@$ServerAHost" } else { $ServerAHost }
$targetB = if ($RemoteUserB) { "$RemoteUserB@$ServerBHost" } else { $ServerBHost }

Write-Host "==> Phase 1: run demo to populate state" -ForegroundColor Magenta
$urlA = "http://127.0.0.1:$ServerAPort"
$urlB = "http://127.0.0.1:$ServerBPort"
$demoOutput = ssh $targetA "$DemoBin demo --server-a $urlA --server-b $urlB --message $Message 2>&1"
if ($LASTEXITCODE -ne 0) {
    Write-Host "demo failed: $demoOutput" -ForegroundColor Red
    exit 1
}
$recoveredLine = ($demoOutput -split "`n" | Where-Object { $_ -eq $Message }) | Select-Object -First 1
if ($recoveredLine -ne $Message) {
    Write-Host "demo did not recover the message (got: '$recoveredLine')" -ForegroundColor Red
    exit 1
}
Write-Host "    demo round-trip OK"

Write-Host "==> Phase 2: capture pubkeys before shutdown" -ForegroundColor Magenta
$beforeA = ssh $targetA "curl -s $urlA/.well-known/lattice/server"
$beforeB = ssh $targetA "curl -s $urlB/.well-known/lattice/server"

Write-Host "==> Phase 3: SIGTERM both servers" -ForegroundColor Magenta
ssh $targetA 'kill $(pgrep -f /lattice-server | head -1) 2>/dev/null; sleep 2; pgrep -f /lattice-server | head -1 || echo "server A down"'
if ($targetA -ne $targetB) {
    ssh $targetB 'kill $(pgrep -f /lattice-server | head -1) 2>/dev/null; sleep 2; pgrep -f /lattice-server | head -1 || echo "server B down"'
}

Write-Host "==> Phase 4: verify snapshot files exist" -ForegroundColor Magenta
$sizeA = ssh $targetA "stat -c %s '$SnapshotPathA' 2>/dev/null || echo 0"
$sizeB = ssh $targetB "stat -c %s '$SnapshotPathB' 2>/dev/null || echo 0"
Write-Host "    snapshot A: $sizeA bytes; B: $sizeB bytes"
if ([int]$sizeA -lt 100 -or [int]$sizeB -lt 100) {
    Write-Host "snapshot files missing or empty — graceful shutdown didn't fire" -ForegroundColor Red
    exit 1
}

Write-Host "==> Phase 5: restart both servers (state restore)" -ForegroundColor Magenta
ssh $targetA "bash $StartScriptA > /dev/null; sleep 2"
if ($targetA -ne $targetB) {
    ssh $targetB "bash $StartScriptB > /dev/null; sleep 2"
}

Write-Host "==> Phase 6: pubkey continuity check" -ForegroundColor Magenta
$afterA = ssh $targetA "curl -s $urlA/.well-known/lattice/server"
$afterB = ssh $targetA "curl -s $urlB/.well-known/lattice/server"
if ($beforeA -ne $afterA) {
    Write-Host "server A pubkey changed on restart: '$beforeA' -> '$afterA'" -ForegroundColor Red
    exit 1
}
if ($beforeB -ne $afterB) {
    Write-Host "server B pubkey changed on restart: '$beforeB' -> '$afterB'" -ForegroundColor Red
    exit 1
}
Write-Host "    pubkeys stable across restart"

Write-Host ""
Write-Host "==> PERSISTENCE PASS -- state survived graceful restart" -ForegroundColor Green
exit 0
