<#
.SYNOPSIS
    M3 per-action CLI end-to-end test.

.DESCRIPTION
    Drives the per-action `lattice` CLI (init / create-and-invite /
    accept / send / recv) across two `lattice-server` instances with
    persistent on-disk state per identity. Proves the file-backed
    storage providers + per-process subcommand flow work, which is
    what real deployment uses.

    Each side ("alice" and "bob") gets its own `<TEMP>/lattice-e2e/
    {alice,bob}/.lattice/` home directory containing identity.json
    plus the file-backed mls-rs stores.
#>

[CmdletBinding()]
param(
    [string]$Message = "hello from per-action CLI",
    [int]$PortA = 4443,
    [int]$PortB = 4444,
    [int]$BootSeconds = 3,
    [string]$GroupId = "lattice-act-test"  # must be 16 ASCII bytes
)

$ErrorActionPreference = "Continue"
$ROOT = (Resolve-Path "$PSScriptRoot\..").Path
Push-Location $ROOT

. "$ROOT\scripts\env-setup.ps1"

Write-Host ""
Write-Host "==> Building workspace" -ForegroundColor Magenta
$cargo = Start-Process -FilePath "cargo" -ArgumentList "build", "--workspace", "--bins" `
    -NoNewWindow -Wait -PassThru
if ($cargo.ExitCode -ne 0) {
    Write-Host "build failed (exit $($cargo.ExitCode))" -ForegroundColor Red
    Pop-Location
    exit 1
}

$BinServer = Join-Path $ROOT "target\debug\lattice-server.exe"
$BinCli = Join-Path $ROOT "target\debug\lattice.exe"

# Per-side dirs.
$AliceDir = New-Item -ItemType Directory -Force `
    -Path "$env:TEMP\lattice-e2e\alice" | Select-Object -ExpandProperty FullName
$BobDir = New-Item -ItemType Directory -Force `
    -Path "$env:TEMP\lattice-e2e\bob" | Select-Object -ExpandProperty FullName
$ServerAKey = Join-Path "$env:TEMP\lattice-e2e\server-a" "federation.key"
$ServerBKey = Join-Path "$env:TEMP\lattice-e2e\server-b" "federation.key"
foreach ($p in @($ServerAKey, $ServerBKey)) {
    if (Test-Path $p) { Remove-Item -Force $p }
    $dir = Split-Path $p -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
}
# Clear prior state so re-runs start clean.
foreach ($d in @($AliceDir, $BobDir)) {
    Get-ChildItem -Path $d -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
}

function Start-Lattice-Server {
    param([int]$Port, [string]$KeyPath, [string]$Label)
    Write-Host "==> Launching $Label on port $Port" -ForegroundColor Magenta
    $env_ps = @{
        "LATTICE__SERVER__BIND_ADDR" = "127.0.0.1:$Port"
        "LATTICE__FEDERATION_KEY_PATH" = $KeyPath
        "LATTICE__DATABASE_URL" = "postgres://noop@localhost/noop"
        "RUST_LOG" = "lattice_server=info,axum=warn"
    }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $BinServer
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    foreach ($k in $env_ps.Keys) { $psi.EnvironmentVariables[$k] = $env_ps[$k] }
    [System.Diagnostics.Process]::Start($psi)
}

function Invoke-Cli {
    param([string]$Label, [string]$ArgString)
    Write-Host "  >> $Label" -ForegroundColor Cyan
    $proc = Start-Process -FilePath $BinCli -ArgumentList $ArgString `
        -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput "$env:TEMP\lattice-e2e\cli-stdout.txt"
    if ($proc.ExitCode -ne 0) {
        throw "$Label failed (exit $($proc.ExitCode))"
    }
    Get-Content "$env:TEMP\lattice-e2e\cli-stdout.txt" -Raw
}

$ServerA = Start-Lattice-Server -Port $PortA -KeyPath $ServerAKey -Label "Server A"
$ServerB = Start-Lattice-Server -Port $PortB -KeyPath $ServerBKey -Label "Server B"

Write-Host "==> Waiting $BootSeconds s for servers to bind" -ForegroundColor Magenta
Start-Sleep -Seconds $BootSeconds

$exitCode = 1
try {
    # Verify well-known on both.
    foreach ($spec in @(@{Port=$PortA;Name="A"}, @{Port=$PortB;Name="B"})) {
        $url = "http://127.0.0.1:$($spec.Port)/.well-known/lattice/server"
        $r = Invoke-RestMethod -Uri $url -TimeoutSec 5
        Write-Host "Server $($spec.Name): wire_version=$($r.wire_version) pubkey=$($r.federation_pubkey_b64.Substring(0, 12))..." -ForegroundColor Cyan
    }

    Write-Host ""
    Write-Host "==> Init Alice on Server A" -ForegroundColor Magenta
    $env:RUST_LOG = "lattice=warn"
    $alice_user = (Invoke-Cli "alice init" `
        ("init --server http://127.0.0.1:{0} --name alice --home `"{1}`"" -f $PortA, $AliceDir)).Trim()
    Write-Host "alice user_id = $alice_user"

    Write-Host "==> Init Bob on Server B" -ForegroundColor Magenta
    $bob_user = (Invoke-Cli "bob init" `
        ("init --server http://127.0.0.1:{0} --name bob --home `"{1}`"" -f $PortB, $BobDir)).Trim()
    Write-Host "bob user_id = $bob_user"

    Write-Host "==> Alice creates group and invites Bob across federation" -ForegroundColor Magenta
    Invoke-Cli "alice create-and-invite" `
        ('create-and-invite --server http://127.0.0.1:{0} --group-id "{1}" --invitee-server http://127.0.0.1:{2} --invitee-user-b64 "{3}" --home "{4}"' `
            -f $PortA, $GroupId, $PortB, $bob_user, $AliceDir) | Out-Null

    Start-Sleep -Milliseconds 500  # let federation push land

    Write-Host "==> Bob accepts Welcome from Server B" -ForegroundColor Magenta
    Invoke-Cli "bob accept" `
        ('accept --server http://127.0.0.1:{0} --group-id "{1}" --home "{2}"' `
            -f $PortB, $GroupId, $BobDir) | Out-Null

    Write-Host "==> Alice sends a message via Server A" -ForegroundColor Magenta
    Invoke-Cli "alice send" `
        ('send --server http://127.0.0.1:{0} --group-id "{1}" --message "{2}" --home "{3}"' `
            -f $PortA, $GroupId, ($Message -replace '"', '\"'), $AliceDir) | Out-Null

    Write-Host "==> Bob receives" -ForegroundColor Magenta
    $recovered = (Invoke-Cli "bob recv" `
        ('recv --server http://127.0.0.1:{0} --group-id "{1}" --timeout 5 --home "{2}"' `
            -f $PortA, $GroupId, $BobDir)).Trim()
    Write-Host "recovered = $recovered" -ForegroundColor Yellow

    if ($recovered -eq $Message) {
        Write-Host ""
        Write-Host "==> E2E PER-ACTION PASS -- federated bridge with persistent state" -ForegroundColor Green
        $exitCode = 0
    } else {
        Write-Host ""
        Write-Host "==> E2E FAIL -- expected '$Message' got '$recovered'" -ForegroundColor Red
    }
} catch {
    Write-Host "E2E exception: $_" -ForegroundColor Red
} finally {
    Write-Host ""
    Write-Host "==> Tearing down servers" -ForegroundColor Magenta
    foreach ($p in @($ServerA, $ServerB)) {
        if ($p -and -not $p.HasExited) {
            try { $p.Kill() } catch { }
            try { $p.WaitForExit(2000) | Out-Null } catch { }
        }
    }
    Pop-Location
}
exit $exitCode
