/*
 * cb_proc.c - PsSetCreateProcessNotifyRoutineEx wiring.
 * Called at PASSIVE_LEVEL by the kernel for every process create/exit on the box;
 * we filter to PIDs in our TargetSet (and grow the set on parent->child).
 */
#include "driver.h"
#include <ntstrsafe.h>

static volatile LONG g_proc_installed;

static VOID NTAPI ProcessNotifyEx(
    _Inout_   PEPROCESS Process,
    _In_      HANDLE    ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    ULONG pid    = HandleToULong(ProcessId);
    ULONG parent;
    WCHAR line[APIMON_MAX_TEXT_WCHARS];

    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo != NULL)
    {
        /* CREATE */
        parent = HandleToULong(CreateInfo->ParentProcessId);

        TargetMaybeAddChild(parent, pid);

        if (TargetContains(pid))
        {
            PCUNICODE_STRING img = CreateInfo->ImageFileName;
            PCUNICODE_STRING cmd = CreateInfo->CommandLine;
            ULONG creator = HandleToULong(CreateInfo->CreatingThreadId.UniqueThread);

            RtlStringCchPrintfW(line, ARRAYSIZE(line),
                L"PROCESS_CREATE pid=%u parent=%u creator_tid=%u image=\"%wZ\" cmd=\"%wZ\"",
                pid, parent, creator,
                img ? img : NULL,
                cmd ? cmd : NULL);

            EventEnqueueText(APIMON_SOURCE_KERNEL, APIMON_KSUB_PROC_CREATE,
                             pid, creator, line);
        }
    }
    else
    {
        /* EXIT */
        if (TargetContains(pid))
        {
            RtlStringCchPrintfW(line, ARRAYSIZE(line),
                L"PROCESS_EXIT pid=%u", pid);
            EventEnqueueText(APIMON_SOURCE_KERNEL, APIMON_KSUB_PROC_EXIT,
                             pid, 0, line);
            TargetRemove(pid);
        }
    }
}

NTSTATUS CbProcessInstall(VOID)
{
    NTSTATUS s = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyEx, FALSE);
    if (NT_SUCCESS(s))
        InterlockedExchange(&g_proc_installed, 1);
    return s;
}

VOID CbProcessUninstall(VOID)
{
    if (InterlockedExchange(&g_proc_installed, 0) == 1)
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyEx, TRUE);
}
