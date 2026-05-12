/*
 * target.c - tracks which PIDs we want to report on. The first PID is set by
 * IOCTL_APIMON_SET_TARGET_PID; descendants get added in cb_proc.c when their
 * parent is in our set.
 */
#include "driver.h"

static KSPIN_LOCK g_pid_lock;
static ULONG      g_pids[APIMON_MAX_PIDS];
static ULONG      g_pid_count;

VOID TargetInit(VOID)
{
    KeInitializeSpinLock(&g_pid_lock);
    RtlZeroMemory(g_pids, sizeof(g_pids));
    g_pid_count = 0;
}

static BOOLEAN TargetContainsLocked(ULONG pid)
{
    ULONG i;
    for (i = 0; i < g_pid_count; i++)
        if (g_pids[i] == pid) return TRUE;
    return FALSE;
}

VOID TargetSet(ULONG pid)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_pid_lock, &irql);
    g_pid_count = 0;
    if (pid != 0)
    {
        g_pids[0] = pid;
        g_pid_count = 1;
    }
    KeReleaseSpinLock(&g_pid_lock, irql);
}

VOID TargetClear(VOID)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_pid_lock, &irql);
    g_pid_count = 0;
    KeReleaseSpinLock(&g_pid_lock, irql);
}

BOOLEAN TargetContains(ULONG pid)
{
    KIRQL   irql;
    BOOLEAN found;
    KeAcquireSpinLock(&g_pid_lock, &irql);
    found = TargetContainsLocked(pid);
    KeReleaseSpinLock(&g_pid_lock, irql);
    return found;
}

VOID TargetMaybeAddChild(ULONG parentPid, ULONG childPid)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_pid_lock, &irql);
    if (TargetContainsLocked(parentPid) &&
        !TargetContainsLocked(childPid) &&
        g_pid_count < APIMON_MAX_PIDS)
    {
        g_pids[g_pid_count++] = childPid;
    }
    KeReleaseSpinLock(&g_pid_lock, irql);
}

VOID TargetRemove(ULONG pid)
{
    KIRQL irql;
    ULONG i;
    KeAcquireSpinLock(&g_pid_lock, &irql);
    for (i = 0; i < g_pid_count; i++)
    {
        if (g_pids[i] == pid)
        {
            g_pids[i] = g_pids[g_pid_count - 1];
            g_pid_count--;
            break;
        }
    }
    KeReleaseSpinLock(&g_pid_lock, irql);
}
