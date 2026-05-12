/* hook_common.h - shared types/macros for the Hook DLL. */
#ifndef APIMON_HOOK_COMMON_H
#define APIMON_HOOK_COMMON_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <strsafe.h>
#include "../apimon_proto.h"

extern HANDLE        g_hHeap;
extern volatile LONG g_log_disabled;
extern DWORD         g_tlsInHook;
extern volatile LONG g_in_init;     /* 1 until DllMain finishes - keeps the
                                       trampoline handler from logging on
                                       calls our own DllMain makes (DbgLog,
                                       CreateFile etc), which would loop
                                       through the hooked kernel32 IAT and
                                       deadlock under loader-lock. */

/* log_client API */
BOOL  LogInit(void);
void  LogShutdown(void);
void  LogSendText(UINT32 source, UINT32 subcategory, LPCWSTR text);
void  LogPrintf(UINT32 source, UINT32 subcategory, LPCWSTR fmt, ...);

/* iat_hook.c - inline-hook engine on top of MinHook.
 *   HooksInstall() creates the hooks (queued, NOT yet active).
 *   HooksEnable()  activates them (calls MH_EnableHook). Must be called
 *                  OUTSIDE loader-lock or MinHook's SuspendThread can
 *                  deadlock with loader workers.
 */
DWORD HooksInstall(void);
void  HooksEnable(void);

#endif
