/*
 * imports.c - one-shot resolver. We deliberately use kernel32 only; loading
 * user32 (for wvsprintfW) is gated by LoadLibrary because user32 may be
 * absent from console-only host processes.
 */
#include "imports.h"

APIMON_IMPORTS g_imp;
ULONG_PTR      g_self_base = 0;
ULONG_PTR      g_self_end  = 0;

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

    /* Compute our own DLL's [base, base+size) so CommonHandler can drop
     * events whose caller_addr lies inside us (we don't want to log calls
     * that our own LogPrintf / patcher / trampoline-back makes through
     * the kernel32 thunk - those would just be noise from APIHook*.dll). */
    {
        HMODULE self = NULL;
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCWSTR)(ULONG_PTR)ImpResolve, &self);
        if (self != NULL) {
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)self;
            if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)self + dos->e_lfanew);
                if (nt->Signature == IMAGE_NT_SIGNATURE) {
                    g_self_base = (ULONG_PTR)self;
                    g_self_end  = g_self_base + nt->OptionalHeader.SizeOfImage;
                }
            }
        }
    }

    return TRUE;
}
