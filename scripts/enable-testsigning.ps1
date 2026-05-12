# enable-testsigning.ps1
# Enables Test Mode in BCD so self-signed kernel drivers will load. Reboot required.
# Run as Administrator.

$current = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Run PowerShell as Administrator." -ForegroundColor Red
    exit 1
}

bcdedit /set testsigning on
Write-Host ""
Write-Host "Test Mode is now enabled in BCD." -ForegroundColor Green
Write-Host "Reboot for the change to take effect." -ForegroundColor Yellow
Write-Host "After reboot a 'Test Mode' watermark appears in the bottom-right corner - this is expected." -ForegroundColor Yellow
Write-Host ""
Write-Host "Note: with Secure Boot enabled, Test Mode does NOT work." -ForegroundColor Yellow
Write-Host "      Disable Secure Boot in UEFI, or use a kernel debugger." -ForegroundColor Yellow
