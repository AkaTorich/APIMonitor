/*
 * inject_apc.c - kernel-mode APC-based DLL injection.
 *
 * Use case: the target process refuses standard user-mode injection (e.g. it's
 * a PPL, an anti-malware service, or has set ProcessDynamicCodePolicy /
 * ProcessExtensionPolicy mitigations that block CreateRemoteThread). From the
 * kernel we can:
 *   1. Find EPROCESS by PID via PsLookupProcessByProcessId.
 *   2. Attach to its address space (KeStackAttachProcess) and ZwAllocateVirtualMemory
 *      a small buffer for the wide DLL path. RtlCopyMemory the path in. Detach.
 *   3. Find a suitable user-mode thread in the target via PsLookupThreadByThreadId
 *      (we walk PsGetNextProcessThread). Skip system threads.
 *   4. Allocate a KAPC, KeInitializeApc(KernelMode rundown -> NormalRoutine in user mode).
 *      NormalRoutine = address of LoadLibraryW (same VA in every process of a
 *      given session because kernel32 is per-boot ASLR'd). NormalContext = path ptr.
 *   5. KeInsertQueueApc with TestAlert so the target picks the APC up at the next
 *      alertable wait. For initially-suspended targets the very first ResumeThread
 *      fires the APC.
 *
 * The user-mode side of the APC will execute LoadLibraryW(path), exactly like
 * a CreateRemoteThread would, but bypassing the user-mode access checks that
 * ZwOpenProcess(PROCESS_VM_OPERATION) rejects on protected processes.
 */
#include "driver.h"

/* Standard exported PS functions. */
NTKERNELAPI NTSTATUS NTAPI PsLookupProcessByProcessId(_In_ HANDLE Pid, _Out_ PEPROCESS *Process);
NTKERNELAPI NTSTATUS NTAPI PsLookupThreadByThreadId (_In_ HANDLE Tid, _Out_ PETHREAD  *Thread);
NTKERNELAPI HANDLE   NTAPI PsGetThreadProcessId(_In_ PETHREAD Thread);

/* KAPC_ENVIRONMENT is internal to the kernel and not exposed by ntifs.h - declare it. */
typedef enum _KAPC_ENVIRONMENT {
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
} KAPC_ENVIRONMENT;

/* Undocumented APC layout we need to call KeInitializeApc directly. */
typedef VOID (NTAPI *PKNORMAL_ROUTINE)(PVOID, PVOID, PVOID);
typedef VOID (NTAPI *PKKERNEL_ROUTINE)(struct _KAPC *, PKNORMAL_ROUTINE *,
                                       PVOID *, PVOID *, PVOID *);
typedef VOID (NTAPI *PKRUNDOWN_ROUTINE)(struct _KAPC *);

NTKERNELAPI VOID NTAPI KeInitializeApc(
    _Inout_ PRKAPC Apc,
    _In_    PRKTHREAD Thread,
    _In_    KAPC_ENVIRONMENT Environment,
    _In_    PKKERNEL_ROUTINE  KernelRoutine,
    _In_opt_ PKRUNDOWN_ROUTINE RundownRoutine,
    _In_opt_ PKNORMAL_ROUTINE  NormalRoutine,
    _In_    KPROCESSOR_MODE    ProcessorMode,
    _In_opt_ PVOID             NormalContext);

NTKERNELAPI BOOLEAN NTAPI KeInsertQueueApc(
    _Inout_ PRKAPC Apc,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2,
    _In_     KPRIORITY Increment);

NTKERNELAPI VOID NTAPI KeTestAlertThread(_In_ KPROCESSOR_MODE AlertMode);

#define APIMON_INJECT_TAG  'jIPA'

typedef struct _APIMON_APC_CTX {
    KAPC   apc;
    PVOID  remote_path;
    SIZE_T remote_size;
    PEPROCESS  proc;
} APIMON_APC_CTX, *PAPIMON_APC_CTX;

/* Kernel routine: runs at APC_LEVEL, frees the APC bookkeeping memory. */
static VOID NTAPI ApcKernelRoutine(
    _In_ PRKAPC Apc,
    _Inout_ PKNORMAL_ROUTINE *NormalRoutine,
    _Inout_ PVOID *NormalContext,
    _Inout_ PVOID *SystemArgument1,
    _Inout_ PVOID *SystemArgument2)
{
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    /* Free the APC bookkeeping. The remote buffer is intentionally leaked -
     * the loaded DLL lives on, the path string is harmless 520B. */
    {
        PAPIMON_APC_CTX ctx = CONTAINING_RECORD(Apc, APIMON_APC_CTX, apc);
        if (ctx->proc) ObDereferenceObject(ctx->proc);
        ExFreePoolWithTag(ctx, APIMON_INJECT_TAG);
    }
}

/* Optional rundown - if the target thread/process exits before the APC fires.
 * Same job: free our state. */
static VOID NTAPI ApcRundownRoutine(_In_ PRKAPC Apc)
{
    PAPIMON_APC_CTX ctx = CONTAINING_RECORD(Apc, APIMON_APC_CTX, apc);
    if (ctx->proc) ObDereferenceObject(ctx->proc);
    ExFreePoolWithTag(ctx, APIMON_INJECT_TAG);
}

/* Allocate a buffer of cb bytes inside the target process (must be attached). */
static NTSTATUS AllocInTarget(_In_ SIZE_T cb, _Out_ PVOID *OutAddr)
{
    PVOID    base = NULL;
    SIZE_T   size = cb;
    NTSTATUS s;

    *OutAddr = NULL;
    s = ZwAllocateVirtualMemory(ZwCurrentProcess(), &base, 0, &size,
                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(s)) return s;
    *OutAddr = base;
    return STATUS_SUCCESS;
}

NTSTATUS InjectDllViaApc(ULONG pid, ULONG tid, PVOID llAddr, PCWSTR dllPath)
{
    PEPROCESS    proc = NULL;
    PETHREAD     thread = NULL;
    KAPC_STATE   apcState;
    NTSTATUS     status;
    PVOID        remoteBuf = NULL;
    SIZE_T       cb;
    PAPIMON_APC_CTX ctx = NULL;

    if (pid == 0 || tid == 0 || llAddr == NULL || dllPath == NULL) return STATUS_INVALID_PARAMETER;

    cb = (wcslen(dllPath) + 1) * sizeof(WCHAR);
    if (cb < sizeof(WCHAR) || cb > APIMON_MAX_DLL_PATH * sizeof(WCHAR))
        return STATUS_INVALID_PARAMETER;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc);
    if (!NT_SUCCESS(status)) return status;

    /* Resolve the host thread up-front; verify it actually belongs to the
     * target process so the caller can't redirect an APC into another PID. */
    status = PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)tid, &thread);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(proc);
        return status;
    }
    if ((ULONG_PTR)PsGetThreadProcessId(thread) != (ULONG_PTR)pid) {
        ObDereferenceObject(thread);
        ObDereferenceObject(proc);
        return STATUS_INVALID_PARAMETER_MIX;
    }

    /* 1. Attach -> allocate remote buffer -> copy path -> detach. */
    KeStackAttachProcess(proc, &apcState);
    {
        SIZE_T size = cb;
        status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &remoteBuf, 0, &size,
                                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (NT_SUCCESS(status))
            RtlCopyMemory(remoteBuf, dllPath, cb);
    }
    KeUnstackDetachProcess(&apcState);

    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(thread);
        ObDereferenceObject(proc);
        return status;
    }

    /* 3. Build and queue user-mode APC. NormalRoutine == LoadLibraryW. */
    ctx = (PAPIMON_APC_CTX)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*ctx), APIMON_INJECT_TAG);
    if (ctx == NULL) {
        ObDereferenceObject(thread);
        ObDereferenceObject(proc);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    ctx->remote_path = remoteBuf;
    ctx->remote_size = cb;
    ctx->proc        = proc;       /* kept alive until the APC kernel routine fires */

    KeInitializeApc(
        &ctx->apc,
        thread,
        OriginalApcEnvironment,
        ApcKernelRoutine,
        ApcRundownRoutine,
        (PKNORMAL_ROUTINE)llAddr,
        UserMode,
        remoteBuf);

    if (!KeInsertQueueApc(&ctx->apc, NULL, NULL, IO_NO_INCREMENT)) {
        ObDereferenceObject(thread);
        ObDereferenceObject(proc);
        ExFreePoolWithTag(ctx, APIMON_INJECT_TAG);
        return STATUS_UNSUCCESSFUL;
    }

    /* 4. Force an alert so the thread picks up the APC at its next alertable
     * point (e.g. NtTestAlert / WaitForSingleObjectEx). */
    KeTestAlertThread(UserMode);

    ObDereferenceObject(thread);
    /* proc stays referenced; ctx->proc owns it; freed in ApcKernelRoutine/Rundown. */
    return STATUS_SUCCESS;
}
