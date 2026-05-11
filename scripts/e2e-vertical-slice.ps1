<#
.SYNOPSIS
    M3 vertical-slice end-to-end test.

.DESCRIPTION
    Spins up two `lattice-server` instances on ports 4443 and 4444,
    each with its own federation key, then runs `lattice demo` to
    drive Alice (server A) inviting Bob (server B) into a group and
    exchanging an MLS-encrypted message across the federation
    bridge. Exits 0 on success; non-zero on any step's failure.

.NOTES
    Author: Matt Gates (suhteevah)
    Acceptance: docs/HANDOFF.md §6 + docs/ROADMAP.md §M3.
#>

[CmdletBinding()]
param(
    [string]$Message = "hello, lattice",
    [int]$PortA = 4443,
    [int]$PortB = 4444,
    [int]$BootSeconds = 3
)

# Don't treat native-command stderr writes as PowerShell exceptions.
$ErrorActionPreference = "Continue"
$ROOT = (Resolve-Path "$PSScriptRoot\..").Path
Push-Location $ROOT

# Make sure the GNU host is selected (MSYS2 mingw gcc as linker).
. "$ROOT\scripts\env-setup.ps1"

Write-Host ""
Write-Host "==> Building workspace (release flags off for speed)" -ForegroundColor Magenta
# Use Start-Process so we don't have to fight PowerShell's stderr-as-error
# treatment of native commands.
$cargo = Start-Process -FilePath "cargo" `
    -ArgumentList "build", "--workspace", "--bins" `
    -NoNewWindow -Wait -PassThru
if ($cargo.ExitCode -ne 0) {
    Write-Host "build failed (cargo exited $($cargo.ExitCode))" -ForegroundColor Red
    Pop-Location
    exit 1
}

# Working dirs for the two servers' federation keys.
$WorkA = New-Item -ItemType Directory -Force -Path "$env:TEMP\lattice-e2e\server-a"
$WorkB = New-Item -ItemType Directory -Force -Path "$env:TEMP\lattice-e2e\server-b"
$KeyA = Join-Path $WorkA.FullName "federation.key"
$KeyB = Join-Path $WorkB.FullName "federation.key"
Remove-Item -ErrorAction SilentlyContinue $KeyA, $KeyB

$BinServer = Join-Path $ROOT "target\debug\lattice-server.exe"
$BinCli = Join-Path $ROOT "target\debug\lattice.exe"
if (-not (Test-Path $BinServer)) {
    Write-Host "lattice-server binary not found at $BinServer" -ForegroundColor Red
    Pop-Location
    exit 1
}
if (-not (Test-Path $BinCli)) {
    Write-Host "lattice CLI binary not found at $BinCli" -ForegroundColor Red
    Pop-Location
    exit 1
}

# Launch helper.
function Start-Lattice-Server {
    param(
        [int]$Port,
        [string]$KeyPath,
        [string]$Label
    )
    Write-Host "==> Launching $Label on port $Port" -ForegroundColor Magenta
    $env_ps = @{
        "LATTICE__SERVER__BIND_ADDR" = "127.0.0.1:$Port"
        "LATTICE__FEDERATION_KEY_PATH" = $KeyPath
        "LATTICE__DATABASE_URL" = "postgres://noop@localhost/noop" # unused in M3
        "RUST_LOG" = "lattice_server=info,axum=warn"
    }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $BinServer
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    foreach ($k in $env_ps.Keys) {
        $psi.EnvironmentVariables[$k] = $env_ps[$k]
    }
    $p = [System.Diagnostics.Process]::Start($psi)
    return $p
}

$ServerA = Start-Lattice-Server -Port $PortA -KeyPath $KeyA -Label "Server A"
$ServerB = Start-Lattice-Server -Port $PortB -KeyPath $KeyB -Label "Server B"

Write-Host "==> Waiting $BootSeconds s for both servers to bind" -ForegroundColor Magenta
Start-Sleep -Seconds $BootSeconds

# Verify both are responding.
$exitCode = 1
try {
    foreach ($spec in @(@{Port=$PortA;Name="A"}, @{Port=$PortB;Name="B"})) {
        $url = "http://127.0.0.1:$($spec.Port)/.well-known/lattice/server"
        try {
            $r = Invoke-RestMethod -Uri $url -TimeoutSec 5
            Write-Host "Server $($spec.Name): wire_version=$($r.wire_version) pubkey=$($r.federation_pubkey_b64.Substring(0, 12))..." -ForegroundColor Cyan
        } catch {
            throw "server $($spec.Name) at $url is not responding: $_"
        }
    }

    Write-Host ""
    Write-Host "==> Running lattice demo (Alice on A, Bob on B)" -ForegroundColor Magenta
    $env:RUST_LOG = "lattice=info,lattice_crypto=warn,lattice_protocol=warn"
    # Build a single quoted command line; Start-Process's -ArgumentList
    # array splits on commas inside the message string, which we don't
    # want.
    $cmdLine = 'demo --server-a "http://127.0.0.1:{0}" --server-b "http://127.0.0.1:{1}" --message "{2}"' `
        -f $PortA, $PortB, ($Message -replace '"', '\"')
    $cliProc = Start-Process -FilePath $BinCli `
        -ArgumentList $cmdLine `
        -NoNewWindow -Wait -PassThru
    $cliExit = $cliProc.ExitCode

    if ($cliExit -eq 0) {
        Write-Host ""
        Write-Host "==> E2E PASS -- federated message delivered cross-server" -ForegroundColor Green
        $exitCode = 0
    } else {
        Write-Host ""
        Write-Host "==> E2E FAIL -- lattice demo exited $cliExit" -ForegroundColor Red
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
