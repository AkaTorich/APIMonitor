# uninstall-driver.ps1
# Stops service, removes it, deletes copy from System32\drivers. Run as Administrator.

[CmdletBinding()]
param(
    [string] $ServiceName = "APIMonitorDrv"
)

$ErrorActionPreference = "Stop"

$current = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Run PowerShell as Administrator." -ForegroundColor Red
    exit 1
}

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -eq "Running" -or $svc.Status -eq "StartPending") {
        Write-Host "Stopping '$ServiceName'..." -ForegroundColor Cyan
        sc.exe stop $ServiceName | Out-Null
        Start-Sleep -Milliseconds 500
    }
    Write-Host "Deleting '$ServiceName'..." -ForegroundColor Cyan
    sc.exe delete $ServiceName | Out-Null
} else {
    Write-Host "Service '$ServiceName' is not registered." -ForegroundColor Gray
}

$dst = Join-Path $env:SystemRoot "System32\drivers\APIMonitorDrv.sys"
if (Test-Path $dst) {
    Write-Host "Removing $dst" -ForegroundColor Cyan
    Remove-Item $dst -Force
}

Write-Host "Done." -ForegroundColor Green
