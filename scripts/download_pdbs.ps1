# download_pdbs.ps1
#
# Pulls public PDBs from the Microsoft symbol server for the x86 (SysWOW64)
# copies of the system DLLs we want to hook. The PDBs are needed by the
# x86 hook generator to recover stdcall arity from "_Name@N" decorations.

[CmdletBinding()]
param(
    [string]$SymbolDir = 'C:\apimon_pdb',
    [string]$SymbolSrv = 'https://msdl.microsoft.com/download/symbols'
)

$ErrorActionPreference = 'Stop'

$symchk = Join-Path "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\x64" 'symchk.exe'
if (-not (Test-Path $symchk)) { throw "symchk.exe not found at $symchk - install WinDbg / Debugging Tools" }

New-Item -ItemType Directory -Path $SymbolDir -Force | Out-Null

# Same DLL list as dump_winapi_exports.ps1 but pulled from SysWOW64 (x86).
$dlls = @(
    'kernel32.dll', 'kernelbase.dll', 'ntdll.dll',
    'user32.dll', 'gdi32.dll', 'gdi32full.dll', 'win32u.dll',
    'advapi32.dll', 'sechost.dll',
    'ole32.dll', 'combase.dll', 'oleaut32.dll',
    'shell32.dll', 'shlwapi.dll', 'shcore.dll',
    'ws2_32.dll', 'wininet.dll', 'winhttp.dll', 'iphlpapi.dll', 'dnsapi.dll',
    'crypt32.dll', 'bcrypt.dll', 'ncrypt.dll', 'cryptsp.dll', 'wintrust.dll',
    'secur32.dll', 'sspicli.dll',
    'psapi.dll', 'version.dll',
    'comctl32.dll', 'comdlg32.dll',
    'wtsapi32.dll', 'userenv.dll', 'profapi.dll',
    'imm32.dll', 'winmm.dll', 'mpr.dll',
    'msvcrt.dll', 'ucrtbase.dll',
    'imagehlp.dll', 'dbghelp.dll',
    'wldap32.dll', 'urlmon.dll'
)

$srvSpec = "SRV*$SymbolDir*$SymbolSrv"

foreach ($dll in $dlls) {
    $path = Join-Path $env:WinDir "SysWOW64\$dll"
    if (-not (Test-Path $path)) {
        Write-Warning "skip: $dll not found in SysWOW64"
        continue
    }
    Write-Host "  $dll ..."
    & $symchk $path /s $srvSpec | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "symchk returned $LASTEXITCODE for $dll"
    }
}

Write-Host ""
Write-Host "Symbols cached under $SymbolDir"
