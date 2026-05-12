# install-driver.ps1
# Copies APIMonitorDrv.sys to %SystemRoot%\System32\drivers\, registers it as a
# kernel-mode service, and starts it. Run as Administrator.

[CmdletBinding()]
param(
    [string] $Configuration = "Release",
    [string] $ServiceName   = "APIMonitorDrv"
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = Split-Path -Parent $ScriptDir
$SrcSys    = Join-Path $RepoRoot "bin\$Configuration\APIMonitorDrv.sys"
$DstDir    = Join-Path $env:SystemRoot "System32\drivers"
$DstSys    = Join-Path $DstDir "APIMonitorDrv.sys"

if (-not (Test-Path $SrcSys)) {
    Write-Host "Driver file not found: $SrcSys" -ForegroundColor Red
    exit 1
}

$current = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Run PowerShell as Administrator." -ForegroundColor Red
    exit 1
}

$tsLine = (bcdedit /enum '{current}' | Select-String "testsigning") -join " "
if ($tsLine -notmatch "Yes") {
    Write-Host "Warning: Test Mode is OFF. StartService may return ERROR_INVALID_IMAGE_HASH (577)." -ForegroundColor Yellow
    Write-Host "Run:  bcdedit /set testsigning on   then reboot." -ForegroundColor Yellow
}

# Stop and remove existing service so we can overwrite the .sys
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -eq "Running" -or $svc.Status -eq "StartPending") {
        Write-Host "Stopping running service '$ServiceName'..." -ForegroundColor Cyan
        sc.exe stop $ServiceName | Out-Null

        # Wait until SCM reports Stopped (up to 10 seconds), polling every 200 ms.
        $deadline = (Get-Date).AddSeconds(10)
        do {
            Start-Sleep -Milliseconds 200
            $svc.Refresh()
        } while ($svc.Status -ne "Stopped" -and (Get-Date) -lt $deadline)

        if ($svc.Status -ne "Stopped") {
            Write-Host "Service did not stop within 10s (state=$($svc.Status)). Aborting." -ForegroundColor Red
            exit 1
        }
    }
    Write-Host "Removing existing service registration..." -ForegroundColor Cyan
    sc.exe delete $ServiceName | Out-Null

    # SCM marks for delete; the entry actually disappears once all handles close.
    # Brief wait so the next 'sc create' doesn't see it as still-existing.
    Start-Sleep -Milliseconds 500
}

# Copy the .sys to System32\drivers (overwrite if exists)
Write-Host "Copying $SrcSys" -ForegroundColor Cyan
Write-Host "    -> $DstSys" -ForegroundColor Cyan
Copy-Item -Path $SrcSys -Destination $DstSys -Force

Write-Host "Registering service '$ServiceName' -> $DstSys" -ForegroundColor Cyan
sc.exe create $ServiceName binPath= "$DstSys" type= kernel start= demand error= normal DisplayName= $ServiceName

Write-Host "Starting service..." -ForegroundColor Cyan
sc.exe start $ServiceName

Start-Sleep -Milliseconds 500
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    Write-Host "OK: $ServiceName is running." -ForegroundColor Green
} else {
    $state = if ($svc) { $svc.Status } else { "<not found>" }
    Write-Host "Service did not start. State: $state" -ForegroundColor Red
    Write-Host "Run check-environment.ps1 for diagnostics." -ForegroundColor Yellow
    exit 1
}
