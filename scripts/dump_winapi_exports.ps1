# dump_winapi_exports.ps1
#
# Walks dumpbin /exports over a curated set of System32 / SysWOW64 DLLs,
# cross-references the x86 copies against public PDBs (pulled in by
# scripts\download_pdbs.ps1) to recover stdcall arity from "_Name@N"
# decorations, and emits four .inc files consumed by Hook\hooks_generic.c:
#
#   generated_hooks_decls.inc      D(name)                       (x64, unique names)
#   generated_hooks_table.inc      X(name, "module")             (x64, all entries)
#   generated_hooks_x86_decls.inc  D86(name, ret_bytes)          (x86, unique names)
#   generated_hooks_x86_table.inc  X86(name, "module", ret_bytes)(x86, all entries)
#
# Skips:
#   - ordinal-only exports (no name)
#   - C++ mangled names (anything not a plain C identifier)
#   - windows.h macro-mapped names (CreateWindow -> CreateWindowW)
#
# Forwarded exports (kernel32 -> kernelbase) are kept; arity for them is
# resolved by following the forward chain into the target DLL's PDB.

[CmdletBinding()]
param(
    [string]$RepoRoot         = (Split-Path -Parent $PSScriptRoot),
    [string]$SymbolDir        = 'C:\apimon_pdb',
    [string]$DeclsFile        = $null,
    [string]$TableFile        = $null,
    [string]$DeclsX86File     = $null,
    [string]$TableX86File     = $null
)

$ErrorActionPreference = 'Stop'

if (-not $DeclsFile)    { $DeclsFile    = Join-Path $RepoRoot 'Hook\generated_hooks_decls.inc' }
if (-not $TableFile)    { $TableFile    = Join-Path $RepoRoot 'Hook\generated_hooks_table.inc' }
if (-not $DeclsX86File) { $DeclsX86File = Join-Path $RepoRoot 'Hook\generated_hooks_x86_decls.inc' }
if (-not $TableX86File) { $TableX86File = Join-Path $RepoRoot 'Hook\generated_hooks_x86_table.inc' }

# --- locate dumpbin and pdb_export -------------------------------------------------

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { throw "vswhere.exe not found at $vswhere" }
$vsRoot = & $vswhere -latest -prerelease -products * -property installationPath
if (-not $vsRoot) { throw "Visual Studio installation not found via vswhere" }

$dumpbin = Get-ChildItem -Path "$vsRoot\VC\Tools\MSVC" -Filter dumpbin.exe -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match 'Hostx64\\x64' } |
    Select-Object -First 1
if (-not $dumpbin) { throw "dumpbin.exe (Hostx64/x64) not found under $vsRoot\VC\Tools\MSVC" }
$dumpbinPath = $dumpbin.FullName

$pdbExport = Join-Path $RepoRoot 'tools\PdbExport\pdb_export.exe'
if (-not (Test-Path $pdbExport)) {
    throw "pdb_export.exe not built. Run tools\PdbExport\build.ps1 first."
}
Write-Host "dumpbin   : $dumpbinPath"
Write-Host "pdb_export: $pdbExport"
Write-Host "symbols   : $SymbolDir"
Write-Host ""

# --- DLL list ----------------------------------------------------------------------

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

$cKeywords = @{
    'auto'=1;'break'=1;'case'=1;'char'=1;'const'=1;'continue'=1;'default'=1
    'do'=1;'double'=1;'else'=1;'enum'=1;'extern'=1;'float'=1;'for'=1;'goto'=1
    'if'=1;'int'=1;'long'=1;'register'=1;'return'=1;'short'=1;'signed'=1
    'sizeof'=1;'static'=1;'struct'=1;'switch'=1;'typedef'=1;'union'=1
    'unsigned'=1;'void'=1;'volatile'=1;'while'=1
}
# windows.h macro-maps the bare name to *A/*W; if we hook the bare name
# our wrapper Hook_g_CreateWindow expands to Hook_g_CreateWindowW and
# clashes with the real -W wrapper. Nothing else is blacklisted - the Hook
# DLL avoids recursion by calling kernel32/user32 through GetProcAddress'd
# function pointers (see Hook\imports.c) instead of static IAT imports.
$blacklist = @{
    'CreateWindow'=1;'CreateDialog'=1;'GetMessage'=1;'PeekMessage'=1
    'DispatchMessage'=1;'SendMessage'=1;'PostMessage'=1
}
$nameRe = '^[A-Za-z_][A-Za-z0-9_]*$'

# --- helpers -----------------------------------------------------------------------

function Get-ExportTable {
    param([string]$DllPath)
    # Returns array of pscustomobjects: Name, Rva, Forwarder.
    # Forwarder is "TARGETDLL.TargetName" string or $null.
    $rows = New-Object System.Collections.Generic.List[object]
    $output = & $dumpbinPath /exports $DllPath 2>$null
    if ($LASTEXITCODE -ne 0) { return $rows }

    $inTable = $false
    foreach ($line in $output) {
        if ($line -match '^\s+ordinal\s+hint\s+RVA\s+name\s*$') { $inTable = $true; continue }
        if (-not $inTable) { continue }

        # Forwarded entry: "    1   0          name (forwarded to TARGET.NAME)"
        if ($line -match '^\s*\d+\s+[0-9A-Fa-f]+\s+([^\s\(]+)\s+\(forwarded to (.+?)\)\s*$') {
            $rows.Add([pscustomobject]@{
                Name      = $matches[1]
                Rva       = 0
                Forwarder = $matches[2]
            })
            continue
        }
        # Normal entry: "    1   0 00012500 Name"
        if ($line -match '^\s*\d+\s+[0-9A-Fa-f]+\s+([0-9A-Fa-f]+)\s+(\S+)\s*$') {
            $rows.Add([pscustomobject]@{
                Name      = $matches[2]
                Rva       = [Convert]::ToInt64($matches[1], 16)
                Forwarder = $null
            })
            continue
        }
        if ($line -match '^\s*Summary\s*$') { break }
        if ($line -match '^\s*$' -and $rows.Count -gt 0) { break }
    }
    return ,$rows
}

function Get-PdbRvaToArity {
    # Reads PDB via pdb_export.exe and builds rva -> arity_bytes (or -1 if unknown).
    # @N suffix means stdcall with N bytes of args. No @ means cdecl/unknown.
    param([string]$PdbPath)

    $map = @{}
    if (-not (Test-Path $PdbPath)) { return $map }
    $lines = & $pdbExport $PdbPath 2>$null
    if ($LASTEXITCODE -ne 0) { return $map }

    foreach ($line in $lines) {
        # pdb_export.exe writes "rva,name" or "rva,name,nparams". Take the
        # leading rva and the next field; ignore anything after a second
        # comma (nparams metadata isn't used on x86).
        if ($line -notmatch '^(\d+),([^,]+)') { continue }
        $rva  = [int64]$matches[1]
        $name = $matches[2]
        # Skip __imp__ thunks: they live at IAT slots, not at the function body.
        if ($name -like '__imp_*') { continue }
        # Skip C++ mangled (?...).
        if ($name.StartsWith('?')) { continue }

        $arity = -1
        # Strict stdcall decoration: leading underscore, plain identifier, @N
        # where N is 1-3 digits (0..999 bytes; real arity is <= 256). Anything
        # else (huge numeric suffix from COFF type info, fastcall '@@', etc.)
        # is ignored.
        if ($name -match '^_([A-Za-z_][A-Za-z0-9_]*)@(\d{1,3})$') {
            $tail = [int]$matches[2]
            if ($tail -le 256) { $arity = $tail }
        }

        # Prefer entries with known arity; otherwise keep whatever first arrived.
        if (-not $map.ContainsKey($rva)) {
            $map[$rva] = $arity
        } elseif ($map[$rva] -lt 0 -and $arity -ge 0) {
            $map[$rva] = $arity
        }
    }
    return $map
}

function Find-Pdb {
    param([string]$Dll, [string]$Root)
    # symchk lays out under <Root>\<wName>.pdb\<HASH>\<wName>.pdb (the leading 'w'
    # marks WoW64 variants pulled from SysWOW64\). Some DLLs (ntdll, ucrtbase)
    # don't get the prefix; check both.
    $base    = [System.IO.Path]::GetFileNameWithoutExtension($Dll)
    $cands   = @("w$base.pdb", "$base.pdb")
    foreach ($c in $cands) {
        $hits = Get-ChildItem -Path (Join-Path $Root $c) -Recurse -Filter $c -ErrorAction SilentlyContinue
        if ($hits) { return $hits[0].FullName }
    }
    return $null
}

# --- pass 1: harvest exports + pdb arity per DLL -----------------------------------

# Per-DLL data:
#   $dllData[$dll] = @{
#       Exports  = OrderedDict name -> @{ Rva=...; Forwarder=...; ArityBytes=int (-1 unknown) }
#       PdbMap   = hashtable rva -> arity_bytes
#   }
$dllData = New-Object 'System.Collections.Specialized.OrderedDictionary'

foreach ($dll in $dlls) {
    $sysPath  = Join-Path $env:WinDir "System32\$dll"
    $wowPath  = Join-Path $env:WinDir "SysWOW64\$dll"
    if (-not (Test-Path $sysPath)) {
        Write-Warning "skip: $dll not found in System32"
        continue
    }
    Write-Host -NoNewline "  $dll ... "

    # x64 exports drive both x64 generic table and the master "name set" we
    # generate wrappers for. x86 exports may differ slightly but in practice
    # the names overlap for the whole user-mode WinAPI surface.
    $exports = Get-ExportTable $sysPath

    # Filter to plain C identifiers and not blacklisted.
    $clean = New-Object System.Collections.Generic.List[object]
    foreach ($e in $exports) {
        if ($e.Name -notmatch $nameRe) { continue }
        if ($cKeywords.ContainsKey($e.Name)) { continue }
        if ($blacklist.ContainsKey($e.Name)) { continue }
        $clean.Add($e)
    }

    # PDB lookup uses x86 PDB. For x86-arity recovery we ALSO need the x86
    # export table (RVA differs from x64). Build it separately.
    $x86Exports = $null
    if (Test-Path $wowPath) {
        $x86Raw = Get-ExportTable $wowPath
        # Index by name for quick join later.
        $x86Exports = @{}
        foreach ($e in $x86Raw) {
            if ($e.Name -notmatch $nameRe) { continue }
            if ($cKeywords.ContainsKey($e.Name)) { continue }
            if ($blacklist.ContainsKey($e.Name)) { continue }
            $x86Exports[$e.Name] = $e
        }
    } else {
        Write-Warning "skip-x86: $dll not in SysWOW64"
    }

    # PDB
    $pdbPath = Find-Pdb -Dll $dll -Root $SymbolDir
    $pdbMap  = @{}
    if ($pdbPath) {
        $pdbMap = Get-PdbRvaToArity -PdbPath $pdbPath
    } else {
        Write-Warning "no PDB for $dll"
    }

    $dllData.Add($dll, @{
        ExportsX64 = $clean
        ExportsX86 = $x86Exports
        PdbMap     = $pdbMap
    }) | Out-Null

    Write-Host "x64=$($clean.Count) x86=$(if ($x86Exports){$x86Exports.Count}else{0}) pdb=$($pdbMap.Count)"
}

# --- pass 2: resolve x86 arity (with forwarder chain) ------------------------------

function Resolve-X86Arity {
    param([string]$Dll, [string]$Name, [int]$Depth = 0)

    if ($Depth -gt 8) { return -1 }
    if (-not $dllData.Contains($Dll)) { return -1 }
    $d = $dllData[$Dll]
    if (-not $d.ExportsX86) { return -1 }
    if (-not $d.ExportsX86.ContainsKey($Name)) { return -1 }

    $entry = $d.ExportsX86[$Name]
    if ($entry.Forwarder) {
        # "TARGETDLL.TargetName" or "TARGETDLL.#ordinal"
        $fwd = $entry.Forwarder
        $dot = $fwd.IndexOf('.')
        if ($dot -lt 0) { return -1 }
        $tDll  = ($fwd.Substring(0, $dot) + '.dll').ToLowerInvariant()
        $tName = $fwd.Substring($dot + 1)
        if ($tName.StartsWith('#')) { return -1 }   # ordinal-only forward, give up
        return Resolve-X86Arity -Dll $tDll -Name $tName -Depth ($Depth + 1)
    }

    # Direct entry: look up RVA in the PDB map.
    $rva = [int64]$entry.Rva
    if ($d.PdbMap.ContainsKey($rva)) {
        return $d.PdbMap[$rva]
    }
    return -1
}

# --- emit x64 .inc files (same as before) ------------------------------------------

$uniqueNames = New-Object 'System.Collections.Specialized.OrderedDictionary'
$totalEntriesX64 = 0
foreach ($dll in $dllData.Keys) {
    foreach ($e in $dllData[$dll].ExportsX64) {
        if (-not $uniqueNames.Contains($e.Name)) { $uniqueNames.Add($e.Name, 1) | Out-Null }
        $totalEntriesX64++
    }
}

$declLines = New-Object System.Collections.Generic.List[string]
[void]$declLines.Add('/*')
[void]$declLines.Add(' * generated_hooks_decls.inc - autogenerated by scripts\dump_winapi_exports.ps1.')
[void]$declLines.Add(' * One D(name) per UNIQUE function name across the harvested DLLs (x64).')
[void]$declLines.Add(' * DO NOT EDIT BY HAND.')
[void]$declLines.Add(' */')
foreach ($name in $uniqueNames.Keys) { [void]$declLines.Add(("    D({0})" -f $name)) }

$tableLines = New-Object System.Collections.Generic.List[string]
[void]$tableLines.Add('/*')
[void]$tableLines.Add(' * generated_hooks_table.inc - autogenerated. (module, name) pairs (x64).')
[void]$tableLines.Add(' * DO NOT EDIT BY HAND.')
[void]$tableLines.Add(' */')
foreach ($dll in $dllData.Keys) {
    [void]$tableLines.Add('')
    [void]$tableLines.Add("    /* $dll */")
    foreach ($e in $dllData[$dll].ExportsX64) {
        [void]$tableLines.Add(("    X({0,-48}, ""{1}"")" -f $e.Name, $dll))
    }
}

# --- emit x86 .inc files -----------------------------------------------------------

$uniqueNamesX86  = New-Object 'System.Collections.Specialized.OrderedDictionary'
$x86Entries      = New-Object System.Collections.Generic.List[object]
$arityKnown      = 0
$arityUnknown    = 0

foreach ($dll in $dllData.Keys) {
    if (-not $dllData[$dll].ExportsX86) { continue }
    foreach ($name in $dllData[$dll].ExportsX86.Keys) {
        $arity = Resolve-X86Arity -Dll $dll -Name $name
        if ($arity -ge 0) { $arityKnown++ } else { $arityUnknown++ }

        # For unknown arity treat as cdecl (caller-cleanup); ret_bytes = 0 is
        # safe for cdecl, but wrong for unknown stdcall. The wrapper falls back
        # to a tail-jmp in that case so we don't trash the stack either way.
        $retBytes = if ($arity -ge 0) { $arity } else { -1 }

        $x86Entries.Add([pscustomobject]@{ Module = $dll; Name = $name; RetBytes = $retBytes })

        # Per-name arity is the *first* one we see. If a name appears in both
        # kernel32 and kernelbase, the arity is the same (forwarder chain
        # leads to the same body) — record it once.
        if (-not $uniqueNamesX86.Contains($name)) {
            $uniqueNamesX86.Add($name, $retBytes) | Out-Null
        }
    }
}

$declX86 = New-Object System.Collections.Generic.List[string]
[void]$declX86.Add('/*')
[void]$declX86.Add(' * generated_hooks_x86_decls.inc - autogenerated.')
[void]$declX86.Add(' * Per UNIQUE name:')
[void]$declX86.Add(' *   D86K(name, ret_bytes) - stdcall arity recovered from PDB; full wrapper')
[void]$declX86.Add(' *                            (copies args, calls orig, logs return value).')
[void]$declX86.Add(' *   D86U(name)            - arity unknown / cdecl; tail-jmp wrapper (no')
[void]$declX86.Add(' *                            return value, no args - just the name).')
[void]$declX86.Add(' * DO NOT EDIT BY HAND.')
[void]$declX86.Add(' */')
foreach ($name in $uniqueNamesX86.Keys) {
    $rb = $uniqueNamesX86[$name]
    if ($rb -ge 0) {
        [void]$declX86.Add(("    D86K({0,-48}, {1})" -f $name, $rb))
    } else {
        [void]$declX86.Add(("    D86U({0})" -f $name))
    }
}

$tableX86 = New-Object System.Collections.Generic.List[string]
[void]$tableX86.Add('/*')
[void]$tableX86.Add(' * generated_hooks_x86_table.inc - autogenerated.')
[void]$tableX86.Add(' * X86(name, "module") - one per (module, function) pair.')
[void]$tableX86.Add(' * DO NOT EDIT BY HAND.')
[void]$tableX86.Add(' */')
$lastDll = $null
foreach ($e in $x86Entries) {
    if ($e.Module -ne $lastDll) {
        [void]$tableX86.Add('')
        [void]$tableX86.Add("    /* $($e.Module) */")
        $lastDll = $e.Module
    }
    [void]$tableX86.Add(("    X86({0,-48}, ""{1}"")" -f $e.Name, $e.Module))
}

# --- write -------------------------------------------------------------------------

$enc = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllLines($DeclsFile,    $declLines,  $enc)
[System.IO.File]::WriteAllLines($TableFile,    $tableLines, $enc)
[System.IO.File]::WriteAllLines($DeclsX86File, $declX86,    $enc)
[System.IO.File]::WriteAllLines($TableX86File, $tableX86,   $enc)

Write-Host ""
Write-Host "x64: $($uniqueNames.Count) unique names, $totalEntriesX64 (module,name) entries"
Write-Host "x86: $($uniqueNamesX86.Count) unique names, $($x86Entries.Count) entries"
Write-Host "x86 arity: known=$arityKnown unknown=$arityUnknown"
Write-Host ""
Write-Host "Wrote:"
Write-Host "  $DeclsFile"
Write-Host "  $TableFile"
Write-Host "  $DeclsX86File"
Write-Host "  $TableX86File"
