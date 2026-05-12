/*
 * imports.h - direct function pointers to every WinAPI the Hook DLL itself
 * relies on. Resolved once at the top of DllMain via GetProcAddress so that
 * our LogPrintf / TLS guard / IAT patcher never reach back through the
 * kernel32 IAT thunk - that thunk is patched into our own wrapper, which
 * would recurse forever.
 */
#ifndef APIMON_IMPORTS_H
#define APIMON_IMPORTS_H

#include <windows.h>

typedef DWORD  (WINAPI *PFN_TlsAlloc)(VOID);
typedef LPVOID (WINAPI *PFN_TlsGetValue)(DWORD);
typedef BOOL   (WINAPI *PFN_TlsSetValue)(DWORD, LPVOID);

typedef VOID   (WINAPI *PFN_InitializeCriticalSection)(LPCRITICAL_SECTION);
typedef VOID   (WINAPI *PFN_EnterCriticalSection)(LPCRITICAL_SECTION);
typedef VOID   (WINAPI *PFN_LeaveCriticalSection)(LPCRITICAL_SECTION);

typedef HANDLE (WINAPI *PFN_HeapCreate)(DWORD, SIZE_T, SIZE_T);
typedef LPVOID (WINAPI *PFN_HeapAlloc)(HANDLE, DWORD, SIZE_T);
typedef BOOL   (WINAPI *PFN_HeapFree)(HANDLE, DWORD, LPVOID);

typedef HANDLE (WINAPI *PFN_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE (WINAPI *PFN_CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL   (WINAPI *PFN_WriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL   (WINAPI *PFN_CloseHandle)(HANDLE);
typedef DWORD  (WINAPI *PFN_SetFilePointer)(HANDLE, LONG, PLONG, DWORD);

typedef BOOL   (WINAPI *PFN_SetNamedPipeHandleState)(HANDLE, LPDWORD, LPDWORD, LPDWORD);
typedef DWORD  (WINAPI *PFN_GetEnvironmentVariableW)(LPCWSTR, LPWSTR, DWORD);

typedef DWORD  (WINAPI *PFN_GetCurrentProcessId)(VOID);
typedef DWORD  (WINAPI *PFN_GetCurrentThreadId)(VOID);
typedef HANDLE (WINAPI *PFN_GetCurrentProcess)(VOID);
typedef BOOL   (WINAPI *PFN_QueryPerformanceCounter)(LARGE_INTEGER *);

typedef DWORD  (WINAPI *PFN_GetLastError)(VOID);

typedef BOOL   (WINAPI *PFN_DisableThreadLibraryCalls)(HMODULE);
typedef HMODULE(WINAPI *PFN_GetModuleHandleW)(LPCWSTR);
typedef BOOL   (WINAPI *PFN_GetModuleHandleExW)(DWORD, LPCWSTR, HMODULE *);

typedef BOOL   (WINAPI *PFN_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL   (WINAPI *PFN_FlushInstructionCache)(HANDLE, LPCVOID, SIZE_T);

typedef int    (WINAPIV *PFN_wvsprintfW)(LPWSTR, LPCWSTR, va_list);

typedef HANDLE (WINAPI *PFN_CreateFileMappingW)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
typedef LPVOID (WINAPI *PFN_MapViewOfFile)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef BOOL   (WINAPI *PFN_UnmapViewOfFile)(LPCVOID);

typedef BOOL   (WINAPI *PFN_TrySubmitThreadpoolCallback)(PTP_SIMPLE_CALLBACK, PVOID, PTP_CALLBACK_ENVIRON);

typedef struct _APIMON_IMPORTS {
    PFN_TlsAlloc                    pTlsAlloc;
    PFN_TlsGetValue                 pTlsGetValue;
    PFN_TlsSetValue                 pTlsSetValue;

    PFN_InitializeCriticalSection   pInitializeCriticalSection;
    PFN_EnterCriticalSection        pEnterCriticalSection;
    PFN_LeaveCriticalSection        pLeaveCriticalSection;

    PFN_HeapCreate                  pHeapCreate;
    PFN_HeapAlloc                   pHeapAlloc;
    PFN_HeapFree                    pHeapFree;

    PFN_CreateFileA                 pCreateFileA;
    PFN_CreateFileW                 pCreateFileW;
    PFN_WriteFile                   pWriteFile;
    PFN_CloseHandle                 pCloseHandle;
    PFN_SetFilePointer              pSetFilePointer;

    PFN_SetNamedPipeHandleState     pSetNamedPipeHandleState;
    PFN_GetEnvironmentVariableW     pGetEnvironmentVariableW;

    PFN_GetCurrentProcessId         pGetCurrentProcessId;
    PFN_GetCurrentThreadId          pGetCurrentThreadId;
    PFN_GetCurrentProcess           pGetCurrentProcess;
    PFN_QueryPerformanceCounter     pQueryPerformanceCounter;

    PFN_GetLastError                pGetLastError;

    PFN_DisableThreadLibraryCalls   pDisableThreadLibraryCalls;
    PFN_GetModuleHandleW            pGetModuleHandleW;
    PFN_GetModuleHandleExW          pGetModuleHandleExW;

    PFN_VirtualProtect              pVirtualProtect;
    PFN_FlushInstructionCache       pFlushInstructionCache;

    PFN_wvsprintfW                  pwvsprintfW;

    PFN_CreateFileMappingW          pCreateFileMappingW;
    PFN_MapViewOfFile               pMapViewOfFile;
    PFN_UnmapViewOfFile             pUnmapViewOfFile;

    PFN_TrySubmitThreadpoolCallback pTrySubmitThreadpoolCallback;
} APIMON_IMPORTS;

extern APIMON_IMPORTS g_imp;

/* Address ranges of "noise" modules - our own Hook DLL, every DLL under
 * System32/SysWOW64/WinSxS, and the C runtime. CommonHandler drops events
 * whose caller_retaddr lies in any of these ranges.
 *
 * Snapshot is taken at ImpResolve time (PEB walk). Modules loaded later
 * are NOT covered - those are typically user DLLs (plugins, etc.) which
 * we DO want to monitor. */
#define APIMON_MAX_NOISE_RANGES 256
typedef struct _APIMON_NOISE_RANGE {
    ULONG_PTR base;
    ULONG_PTR end;
} APIMON_NOISE_RANGE;

extern APIMON_NOISE_RANGE g_noise_ranges[APIMON_MAX_NOISE_RANGES];
extern volatile LONG       g_noise_count;

/* Returns FALSE if any required function couldn't be resolved. Called once
 * at the very top of DllMain, before any other Hook DLL code runs. */
BOOL ImpResolve(void);

#endif
