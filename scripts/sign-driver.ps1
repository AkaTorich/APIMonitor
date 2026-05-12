# sign-driver.ps1
# Creates a self-signed test certificate (if missing) and signs APIMonitorDrv.sys with it.
# Run as Administrator from PowerShell.

[CmdletBinding()]
param(
    [string] $Configuration  = "Release",
    [string] $CertSubject    = "CN=APIMonitorTest",
    [switch] $WithTimestamp  # off by default - timestamping a freshly-issued self-signed cert often fails
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = Split-Path -Parent $ScriptDir
$SysPath   = Join-Path $RepoRoot "bin\$Configuration\APIMonitorDrv.sys"

if (-not (Test-Path $SysPath)) {
    Write-Host "Driver file not found: $SysPath" -ForegroundColor Red
    Write-Host "Build the solution first (Build -> Build Solution)." -ForegroundColor Yellow
    exit 1
}

$current = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Run PowerShell as Administrator." -ForegroundColor Red
    exit 1
}

$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq $CertSubject } | Select-Object -First 1

if (-not $cert) {
    Write-Host "Creating self-signed certificate '$CertSubject' in LocalMachine\My..." -ForegroundColor Cyan
    $cert = New-SelfSignedCertificate `
        -Subject $CertSubject `
        -Type CodeSigningCert `
        -CertStoreLocation "Cert:\LocalMachine\My" `
        -KeyUsage DigitalSignature `
        -KeyAlgorithm RSA `
        -KeyLength 2048 `
        -NotAfter (Get-Date).AddYears(5) `
        -HashAlgorithm SHA256
    Write-Host "  Thumbprint: $($cert.Thumbprint)" -ForegroundColor Gray
} else {
    Write-Host "Reusing existing certificate '$CertSubject' (Thumbprint $($cert.Thumbprint))" -ForegroundColor Cyan
}

function Copy-CertTo($storeName) {
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, "LocalMachine")
    $store.Open("ReadWrite")
    $exists = $store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
    if (-not $exists) {
        $store.Add($cert)
        Write-Host "  Added to LocalMachine\$storeName" -ForegroundColor Gray
    }
    $store.Close()
}
Copy-CertTo "Root"
Copy-CertTo "TrustedPublisher"

Write-Host "Signing $SysPath ..." -ForegroundColor Cyan
if ($WithTimestamp) {
    $result = Set-AuthenticodeSignature `
        -FilePath $SysPath `
        -Certificate $cert `
        -HashAlgorithm SHA256 `
        -TimestampServer "http://timestamp.digicert.com"
} else {
    $result = Set-AuthenticodeSignature `
        -FilePath $SysPath `
        -Certificate $cert `
        -HashAlgorithm SHA256
}

if ($result.Status -eq "Valid") {
    Write-Host "Done: signature is Valid." -ForegroundColor Green
} else {
    Write-Host "Signing finished with status $($result.Status): $($result.StatusMessage)" -ForegroundColor Yellow
    Write-Host "(For self-signed in Test Mode this is usually fine.)" -ForegroundColor Gray
}

$tsLine = (bcdedit /enum '{current}' | Select-String "testsigning") -join " "
if ($tsLine -notmatch "Yes") {
    Write-Host ""
    Write-Host "Test Mode is OFF. Enable it and reboot:" -ForegroundColor Yellow
    Write-Host "    bcdedit /set testsigning on" -ForegroundColor Yellow
    Write-Host "    shutdown /r /t 0" -ForegroundColor Yellow
}
