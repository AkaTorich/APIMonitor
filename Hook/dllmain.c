/*
 * dllmain.c - Hook DLL entry point.
 *
 * MinHook patched (Freeze() = no-op) so MH_EnableHook no longer suspends
 * other threads. That makes it safe to call from inside DLL_PROCESS_ATTACH
 * under the loader-lock - no more deadlock with loader workers.
 */
#include "hook_common.h"
#include "log_client.h"
#include "imports.h"

extern void HooksEnable(void);

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved)
{
    UNREFERENCED_PARAMETER(hInst);
    UNREFERENCED_PARAMETER(reserved);
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        if (!ImpResolve()) return FALSE;
        if (!RingInit())   return TRUE;
        HooksInstall();
        HooksEnable();
        InterlockedExchange(&g_log_disabled, 0);
        InterlockedExchange(&g_in_init, 0);
        return TRUE;

    case DLL_PROCESS_DETACH:
        RingShutdown();
        return TRUE;

    default:
        return TRUE;
    }
}
