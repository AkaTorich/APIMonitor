/*
 * imports.c - one-shot resolver. We deliberately use kernel32 only; loading
 * user32 (for wvsprintfW) is gated by LoadLibrary because user32 may be
 * absent from console-only host processes.
 */
#include "imports.h"

APIMON_IMPORTS g_imp;

#define R_K32(name) \
    g_imp.p##name = (PFN_##name)GetProcAddress(k32, #name); \
    if (g_imp.p##name == NULL) return FALSE;

BOOL ImpResolve(void)
{
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
    R_K32(QueryPerformanceFrequency);

    R_K32(GetLastError);

    R_K32(DisableThreadLibraryCalls);
    R_K32(GetModuleHandleW);
    R_K32(GetModuleHandleExW);

    R_K32(VirtualProtect);
    R_K32(FlushInstructionCache);

    R_K32(CreateFileMappingW);
    R_K32(MapViewOfFile);
    R_K32(UnmapViewOfFile);

    g_imp.pwvsprintfW = NULL;
    return TRUE;
}
