# setup-driver.ps1 - one-shot driver setup for the test VM.
# Run it once (right-click -> "Run with PowerShell", or from a console).
# It self-elevates, trusts the test certificate, enables Test Mode, reboots if
# needed, and after the reboot installs and starts the driver automatically.

[CmdletBinding()]
param(
    [switch] $Resume,
    [switch] $NoReboot
)

$ErrorActionPreference = "Stop"
$ServiceName = "APIMonitorDrv"
$TaskName    = "APIMonitorDrvSetup"

# --- self-elevate ---
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $a = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($Resume)   { $a = $a + " -Resume" }
    if ($NoReboot) { $a = $a + " -NoReboot" }
    Start-Process powershell -Verb RunAs -ArgumentList $a
    return
}

$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Log  = Join-Path $Here "setup-driver.log"
Start-Transcript -Path $Log -Append -ErrorAction SilentlyContinue | Out-Null

function Find-Near([string]$name) {
    $cands = @("$Here\$name", "$Here\..\$name", "$Here\bin\Release\$name", "$Here\..\bin\Release\$name")
    foreach ($p in $cands) { if (Test-Path $p) { return $p } }
    return $null
}

function Install-Driver {
    $sys = Find-Near "APIMonitorDrv.sys"
    if (-not $sys) { Write-Host "APIMonitorDrv.sys not found next to the script." -ForegroundColor Red; return $false }
    $dst = Join-Path $env:SystemRoot "System32\drivers\APIMonitorDrv.sys"

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -ne "Stopped") { & sc.exe stop $ServiceName | Out-Null; Start-Sleep -Milliseconds 600 }
        & sc.exe delete $ServiceName | Out-Null
        Start-Sleep -Milliseconds 500
    }
    Copy-Item $sys $dst -Force
    & sc.exe create $ServiceName binPath= "$dst" type= kernel start= demand error= normal DisplayName= $ServiceName | Out-Null
    & sc.exe start $ServiceName | Out-Null
    Start-Sleep -Milliseconds 700
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    $state = "none"
    if ($svc) { $state = [string]$svc.Status }
    if ($state -eq "Running") {
        Write-Host "DONE: driver loaded and running. You can start APIMonitor.exe." -ForegroundColor Green
        return $true
    }
    Write-Host "Service did not start (state: $state)." -ForegroundColor Red
    Write-Host "Run check-environment.ps1 - it shows what blocks the load." -ForegroundColor Yellow
    return $false
}

function Trust-Cert {
    $cer = Find-Near "APIMonitorTest.cer"
    if (-not $cer) { Write-Host "APIMonitorTest.cer not found next to the script - skipping trust." -ForegroundColor Yellow; return }
    $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cer)
    foreach ($storeName in @("Root","TrustedPublisher")) {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName,"LocalMachine")
        $store.Open("ReadWrite")
        $have = $false
        foreach ($x in $store.Certificates) { if ($x.Thumbprint -eq $c.Thumbprint) { $have = $true } }
        if (-not $have) { $store.Add($c) }
        $store.Close()
    }
    Write-Host "Test certificate trusted (LocalMachine Root + TrustedPublisher)." -ForegroundColor Green
}

function Get-TestSigning {
    $line = (bcdedit /enum '{current}' | Select-String "testsigning") -join " "
    return ($line -match "Yes")
}

function Test-Blockers {
    $blocked = $false
    try {
        if (Confirm-SecureBootUEFI -ErrorAction Stop) {
            Write-Host "[STOP] Secure Boot is ON - test-signed drivers will not load." -ForegroundColor Red
            Write-Host "       Turn Secure Boot OFF in the VM settings, then run this script again." -ForegroundColor Yellow
            $blocked = $true
        }
    } catch { }
    try {
        $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
        if ($dg.SecurityServicesRunning -contains 2) {
            Write-Host "[STOP] HVCI (Memory Integrity) is running - self-signed drivers are blocked." -ForegroundColor Red
            Write-Host "       Windows Security -> Core Isolation -> Memory Integrity -> Off, reboot." -ForegroundColor Yellow
            $blocked = $true
        }
    } catch { }
    try {
        $sac = (Get-MpComputerStatus -ErrorAction Stop).SmartAppControlState
        if ($sac -eq "On" -or $sac -eq "Eval") {
            Write-Host "[STOP] Smart App Control: $sac - blocks self-signed drivers." -ForegroundColor Red
            $blocked = $true
        }
    } catch { }
    return $blocked
}

try {
    if ($Resume) {
        Write-Host "=== Resuming after reboot ===" -ForegroundColor Cyan
        Trust-Cert
        if (Get-TestSigning) { Install-Driver | Out-Null }
        else { Write-Host "Test Mode is still off (Secure Boot?). Check the VM settings." -ForegroundColor Red }
        & schtasks /Delete /TN $TaskName /F 2>$null | Out-Null
        Write-Host ""
        Write-Host "Log: $Log" -ForegroundColor Gray
        Start-Sleep -Seconds 20
        return
    }

    Write-Host "=== APIMonitor driver setup ===" -ForegroundColor Cyan

    Trust-Cert

    if (Test-Blockers) {
        Write-Host ""
        Write-Host "Fix the [STOP] item above and run this script again." -ForegroundColor Red
        return
    }

    if (Get-TestSigning) {
        Write-Host "Test Mode already on - installing the driver now." -ForegroundColor Green
        Install-Driver | Out-Null
        return
    }

    Write-Host "Enabling Test Mode (a reboot is required)..." -ForegroundColor Cyan
    & bcdedit /set testsigning on | Out-Null

    $tr = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Resume"
    & schtasks /Create /TN $TaskName /TR $tr /SC ONSTART /RU SYSTEM /RL HIGHEST /F | Out-Null
    Write-Host "After the reboot the driver installs automatically." -ForegroundColor Green

    if ($NoReboot) {
        Write-Host "Reboot the VM manually - the install will finish by itself." -ForegroundColor Yellow
        return
    }
    Write-Host "Rebooting in 8 seconds (Ctrl+C to cancel)..." -ForegroundColor Yellow
    Start-Sleep -Seconds 8
    Restart-Computer -Force
}
finally {
    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
}
