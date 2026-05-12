# check-environment.ps1
# Diagnoses why a test-signed kernel driver can't load.
# Reports Test Mode, Secure Boot, HVCI/VBS, and the cert chain status.

$ErrorActionPreference = "Continue"

Write-Host "=== Driver loadability checks ===" -ForegroundColor Cyan
Write-Host ""

# 1. Test Mode
$ts = (bcdedit /enum '{current}' | Select-String "testsigning") -join " "
if ($ts -match "Yes") {
    Write-Host "[OK]  Test Mode is ON." -ForegroundColor Green
} else {
    Write-Host "[!!]  Test Mode is OFF." -ForegroundColor Red
    Write-Host "      Run: bcdedit /set testsigning on   then REBOOT." -ForegroundColor Yellow
}

# 2. Secure Boot
try {
    $sb = Confirm-SecureBootUEFI -ErrorAction Stop
    if ($sb) {
        Write-Host "[!!]  Secure Boot is ON. Test-signed drivers will NOT load." -ForegroundColor Red
        Write-Host "      Disable Secure Boot in UEFI/BIOS, or use a kernel debugger." -ForegroundColor Yellow
    } else {
        Write-Host "[OK]  Secure Boot is OFF." -ForegroundColor Green
    }
} catch {
    Write-Host "[??]  Secure Boot status unknown (likely legacy BIOS): $($_.Exception.Message)" -ForegroundColor Gray
}

# 3. HVCI / VBS / Memory Integrity
try {
    $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
    $hvciRunning = $dg.SecurityServicesRunning -contains 2
    $vbsRunning  = $dg.VirtualizationBasedSecurityStatus -eq 2
    if ($hvciRunning) {
        Write-Host "[!!]  HVCI (Memory Integrity) is RUNNING. Self-signed drivers are blocked." -ForegroundColor Red
        Write-Host "      Settings -> Privacy & Security -> Windows Security ->" -ForegroundColor Yellow
        Write-Host "      Device Security -> Core Isolation -> Memory Integrity -> OFF, then reboot." -ForegroundColor Yellow
    } else {
        Write-Host "[OK]  HVCI / Memory Integrity is OFF." -ForegroundColor Green
    }
    if ($vbsRunning) {
        Write-Host "[!!]  VBS is RUNNING (VirtualizationBasedSecurityStatus=2)." -ForegroundColor Red
        Write-Host "      VBS can silently block test-signed drivers at the VTL level (Error 5 with no CI log)." -ForegroundColor Yellow
        Write-Host "      Disable: bcdedit /set hypervisorlaunchtype off && bcdedit /set vsmlaunchtype off, then reboot." -ForegroundColor Yellow
    }
    Write-Host ("      VirtualizationBasedSecurityStatus = {0}" -f $dg.VirtualizationBasedSecurityStatus) -ForegroundColor Gray
    Write-Host ("      SecurityServicesRunning           = {0}" -f ($dg.SecurityServicesRunning -join ",")) -ForegroundColor Gray
    Write-Host ("      CodeIntegrityPolicyEnforcementStatus = {0}" -f $dg.CodeIntegrityPolicyEnforcementStatus) -ForegroundColor Gray
    Write-Host ("      UsermodeCodeIntegrityPolicyEnforcementStatus = {0}" -f $dg.UsermodeCodeIntegrityPolicyEnforcementStatus) -ForegroundColor Gray
} catch {
    Write-Host "[??]  Could not query DeviceGuard CIM: $($_.Exception.Message)" -ForegroundColor Gray
}

# 3b. Hypervisor launch state (independent of HVCI)
$hl = (bcdedit /enum '{current}' | Select-String "hypervisorlaunchtype") -join " "
if ($hl -match "Auto") {
    Write-Host "[!!]  hypervisorlaunchtype = Auto (Hyper-V/VBS will launch on boot)." -ForegroundColor Red
    Write-Host "      To disable: bcdedit /set hypervisorlaunchtype off" -ForegroundColor Yellow
} elseif ($hl -match "Off") {
    Write-Host "[OK]  hypervisorlaunchtype = Off." -ForegroundColor Green
} else {
    Write-Host ("[??]  hypervisorlaunchtype line: {0}" -f $hl) -ForegroundColor Gray
}

# 4. Driver file + signature
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = Split-Path -Parent $ScriptDir
$SysPath   = Join-Path $RepoRoot "bin\Release\APIMonitorDrv.sys"
if (Test-Path $SysPath) {
    $sig = Get-AuthenticodeSignature $SysPath
    Write-Host "[?]   Driver: $SysPath" -ForegroundColor Cyan
    Write-Host "      Signature status: $($sig.Status)" -ForegroundColor Cyan
    if ($sig.SignerCertificate) {
        Write-Host "      Signer:           $($sig.SignerCertificate.Subject)" -ForegroundColor Cyan
        Write-Host "      Thumbprint:       $($sig.SignerCertificate.Thumbprint)" -ForegroundColor Cyan
        Write-Host "      Valid:            $($sig.SignerCertificate.NotBefore) - $($sig.SignerCertificate.NotAfter)" -ForegroundColor Cyan
    }

    # Cert installed in trusted stores?
    if ($sig.SignerCertificate) {
        $tp = $sig.SignerCertificate.Thumbprint
        $inRoot = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq $tp }
        $inPub  = Get-ChildItem Cert:\LocalMachine\TrustedPublisher | Where-Object { $_.Thumbprint -eq $tp }
        if ($inRoot) { Write-Host "      Installed in LocalMachine\Root            : YES" -ForegroundColor Green }
        else         { Write-Host "      Installed in LocalMachine\Root            : NO"  -ForegroundColor Red   }
        if ($inPub)  { Write-Host "      Installed in LocalMachine\TrustedPublisher: YES" -ForegroundColor Green }
        else         { Write-Host "      Installed in LocalMachine\TrustedPublisher: NO"  -ForegroundColor Red   }
    }
} else {
    Write-Host "[!!]  Driver file not found: $SysPath" -ForegroundColor Red
}

# 5. Smart App Control (Win 11 22H2+)
try {
    $sac = (Get-MpComputerStatus -ErrorAction Stop).SmartAppControlState
    if ($sac -eq "On" -or $sac -eq "Eval") {
        Write-Host "[!!]  Smart App Control: $sac. Blocks self-signed drivers." -ForegroundColor Red
        Write-Host "      Settings -> Privacy & Security -> Windows Security -> App & browser control" -ForegroundColor Yellow
        Write-Host "      -> Smart App Control settings -> Off (note: cannot be re-enabled without reinstall)." -ForegroundColor Yellow
    } else {
        Write-Host "[OK]  Smart App Control: $sac." -ForegroundColor Green
    }
} catch {
    Write-Host "[??]  Smart App Control state unknown: $($_.Exception.Message)" -ForegroundColor Gray
}

# 6. Vulnerable Driver Blocklist
try {
    $vdb = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config" -Name "VulnerableDriverBlocklistEnable" -ErrorAction Stop).VulnerableDriverBlocklistEnable
    if ($vdb -eq 1) {
        Write-Host "[?]   Vulnerable Driver Blocklist: ON (does not block our cert, listed for context)." -ForegroundColor Gray
    } else {
        Write-Host "[OK]  Vulnerable Driver Blocklist: OFF." -ForegroundColor Green
    }
} catch {
    Write-Host "[??]  Vulnerable Driver Blocklist state unknown." -ForegroundColor Gray
}

function Show-Event($e) {
    Write-Host ("[{0}] Id={1} Level={2} Provider={3}" -f $e.TimeCreated, $e.Id, $e.LevelDisplayName, $e.ProviderName) -ForegroundColor Yellow
    $lines = $e.Message -split "`r?`n"
    foreach ($ln in $lines) {
        if ($ln.Trim().Length -gt 0) { Write-Host ("    " + $ln) -ForegroundColor Gray }
    }
    Write-Host ""
}

# 7. Recent CodeIntegrity events (the usual culprit for kernel ACCESS_DENIED)
Write-Host ""
Write-Host "=== Last 5 CodeIntegrity events ===" -ForegroundColor Cyan
try {
    $ev = Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" -MaxEvents 5 -ErrorAction Stop
    if ($ev) { $ev | ForEach-Object { Show-Event $_ } } else { Write-Host "  (none)" -ForegroundColor Gray }
} catch {
    Write-Host "  (log empty or access denied)" -ForegroundColor Gray
}

# 8. Anything in System log mentioning our driver in the last 10 minutes
Write-Host ""
Write-Host "=== System log: APIMonitorDrv entries in last 10 minutes ===" -ForegroundColor Cyan
$cutoff = (Get-Date).AddMinutes(-10)
try {
    $ev = Get-WinEvent -LogName System -MaxEvents 500 -ErrorAction Stop |
            Where-Object { $_.TimeCreated -gt $cutoff -and $_.Message -match "APIMonitorDrv" }
    if ($ev) { $ev | ForEach-Object { Show-Event $_ } } else { Write-Host "  (none)" -ForegroundColor Gray }
} catch {
    Write-Host "  (access denied)" -ForegroundColor Gray
}

# 9. All SCM errors in the last 10 minutes (catches drivers blocked at IO Manager level)
Write-Host ""
Write-Host "=== System log: errors in last 10 minutes ===" -ForegroundColor Cyan
try {
    $ev = Get-WinEvent -LogName System -MaxEvents 500 -ErrorAction Stop |
            Where-Object { $_.TimeCreated -gt $cutoff -and $_.LevelDisplayName -in @("Ошибка","Error","Critical","Критическое") }
    if ($ev) { $ev | Select-Object -First 8 | ForEach-Object { Show-Event $_ } } else { Write-Host "  (none)" -ForegroundColor Gray }
} catch {
    Write-Host "  (access denied)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "Summary: if any [!!] line is red above, fix it before retrying install-driver.ps1." -ForegroundColor Cyan
