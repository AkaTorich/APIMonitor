/*
 * imports.c - one-shot resolver. We deliberately use kernel32 only; loading
 * user32 (for wvsprintfW) is gated by LoadLibrary because user32 may be
 * absent from console-only host processes.
 */
#include "imports.h"

APIMON_IMPORTS    g_imp;
APIMON_NOISE_RANGE g_noise_ranges[APIMON_MAX_NOISE_RANGES];
volatile LONG      g_noise_count = 0;

#if defined(_WIN64)
#define READ_PEB() ((PPEB)__readgsqword(0x60))
#else
#define READ_PEB() ((PPEB)__readfsdword(0x30))
#endif

#include <winternl.h>

typedef struct _APIMON_LDR_ENTRY_LITE {
    LIST_ENTRY      InLoadOrderLinks;
    LIST_ENTRY      InMemoryOrderLinks;
    LIST_ENTRY      InInitializationOrderLinks;
    PVOID           DllBase;
    PVOID           EntryPoint;
    ULONG           SizeOfImage;
    UNICODE_STRING  FullDllName;
    UNICODE_STRING  BaseDllName;
} APIMON_LDR_ENTRY_LITE;

static int WcsContainsCi(const WCHAR *hay, size_t hayLen, const WCHAR *needle)
{
    size_t needleLen = 0;
    while (needle[needleLen]) needleLen++;
    if (needleLen > hayLen) return 0;
    for (size_t i = 0; i + needleLen <= hayLen; i++) {
        size_t j;
        for (j = 0; j < needleLen; j++) {
            WCHAR a = hay[i + j];
            WCHAR b = needle[j];
            if (a >= L'A' && a <= L'Z') a = (WCHAR)(a - L'A' + L'a');
            if (a != b) break;
        }
        if (j == needleLen) return 1;
    }
    return 0;
}

static int IsNoiseModule(const WCHAR *fullPath, size_t fullLen,
                         const WCHAR *baseName, size_t baseLen)
{
    /* system folders */
    if (WcsContainsCi(fullPath, fullLen, L"\\system32\\")) return 1;
    if (WcsContainsCi(fullPath, fullLen, L"\\syswow64\\")) return 1;
    if (WcsContainsCi(fullPath, fullLen, L"\\winsxs\\"))   return 1;

    /* CRT */
    static const WCHAR *crtPrefixes[] = {
        L"ucrtbase", L"msvcrt", L"vcruntime", L"msvcp", L"apihook"
    };
    for (size_t k = 0; k < sizeof(crtPrefixes) / sizeof(crtPrefixes[0]); k++) {
        const WCHAR *p = crtPrefixes[k];
        size_t pl = 0; while (p[pl]) pl++;
        if (baseLen >= pl) {
            int match = 1;
            for (size_t i = 0; i < pl; i++) {
                WCHAR a = baseName[i];
                WCHAR b = p[i];
                if (a >= L'A' && a <= L'Z') a = (WCHAR)(a - L'A' + L'a');
                if (a != b) { match = 0; break; }
            }
            if (match) return 1;
        }
    }
    return 0;
}

static void ScanNoiseRanges(void)
{
    PPEB peb = READ_PEB();
    if (peb == NULL || peb->Ldr == NULL) return;

    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    LONG idx = 0;
    for (PLIST_ENTRY cur = head->Flink; cur != head && idx < APIMON_MAX_NOISE_RANGES; cur = cur->Flink) {
        APIMON_LDR_ENTRY_LITE *e = (APIMON_LDR_ENTRY_LITE *)
            ((BYTE *)cur - FIELD_OFFSET(APIMON_LDR_ENTRY_LITE, InMemoryOrderLinks));

        if (e->DllBase == NULL || e->SizeOfImage == 0) continue;
        if (e->FullDllName.Buffer == NULL || e->BaseDllName.Buffer == NULL) continue;

        size_t fullLen = e->FullDllName.Length / sizeof(WCHAR);
        size_t baseLen = e->BaseDllName.Length / sizeof(WCHAR);

        if (IsNoiseModule(e->FullDllName.Buffer, fullLen,
                          e->BaseDllName.Buffer, baseLen)) {
            g_noise_ranges[idx].base = (ULONG_PTR)e->DllBase;
            g_noise_ranges[idx].end  = (ULONG_PTR)e->DllBase + e->SizeOfImage;
            idx++;
        }
    }
    g_noise_count = idx;
}

#define R_K32(name) \
    g_imp.p##name = (PFN_##name)GetProcAddress(k32, #name); \
    if (g_imp.p##name == NULL) return FALSE;

BOOL ImpResolve(void)
{
    /* GetModuleHandleW(L"kernel32.dll") - this very call goes through our
     * own DLL's kernel32 IAT thunk, but at this moment we have NOT patched
     * anything yet, so it's a normal direct kernel32 call. From this point
     * on we use g_imp.* exclusively. */
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    if (k32 == NULL) return FALSE;

    R_K32(TlsAlloc);
    R_K32(TlsGetValue);
    R_K32(TlsSetValue);

    R_K32(InitializeCriticalSection);
    R_K32(EnterCriticalSection);
    R_K32(LeaveCriticalSection);

    R_K32(HeapCreate);
    R_K32(HeapAlloc);
    R_K32(HeapFree);

    R_K32(CreateFileA);
    R_K32(CreateFileW);
    R_K32(WriteFile);
    R_K32(CloseHandle);
    R_K32(SetFilePointer);

    R_K32(SetNamedPipeHandleState);
    R_K32(GetEnvironmentVariableW);

    R_K32(GetCurrentProcessId);
    R_K32(GetCurrentThreadId);
    R_K32(GetCurrentProcess);
    R_K32(QueryPerformanceCounter);

    R_K32(GetLastError);

    R_K32(DisableThreadLibraryCalls);
    R_K32(GetModuleHandleW);
    R_K32(GetModuleHandleExW);

    R_K32(VirtualProtect);
    R_K32(FlushInstructionCache);

    R_K32(CreateFileMappingW);
    R_K32(MapViewOfFile);
    R_K32(UnmapViewOfFile);

    R_K32(TrySubmitThreadpoolCallback);

    /* No user32 dependency - we don't format anything in the DLL anymore. */
    g_imp.pwvsprintfW = NULL;

    /* Build the noise-range table from currently-loaded modules. Hook DLL
     * itself plus everything from System32/SysWOW64/WinSxS/CRT goes in. */
    ScanNoiseRanges();

    return TRUE;
}
