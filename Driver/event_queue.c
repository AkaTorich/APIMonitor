/*
 * event_queue.c - the central FIFO that receives events from kernel callbacks
 * (any IRQL <= DISPATCH_LEVEL) and feeds them out to user-mode through
 * pending IOCTL_GET_EVENT IRPs (inverted call).
 *
 * Locking:
 *   - g_evt_lock protects g_evt_queue (LIST_ENTRY)
 *   - the IO_CSQ has its own internal locking
 *   - we acquire g_evt_lock at DISPATCH_LEVEL (KeAcquireSpinLock) so callbacks
 *     calling us from APC_LEVEL or PASSIVE_LEVEL all work.
 */
#include "driver.h"
#include <ntstrsafe.h>

#define MAX_QUEUED_EVENTS  4096

static KSPIN_LOCK g_evt_lock;
static LIST_ENTRY g_evt_queue;
static ULONG      g_evt_count;

static IO_CSQ     g_csq;
static KSPIN_LOCK g_csq_lock;
static LIST_ENTRY g_csq_list;

/* ---- CSQ callbacks ---- */

static VOID CsqInsertIrp(_In_ PIO_CSQ Csq, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(Csq);
    InsertTailList(&g_csq_list, &Irp->Tail.Overlay.ListEntry);
}

static VOID CsqRemoveIrp(_In_ PIO_CSQ Csq, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(Csq);
    RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
}

static PIRP CsqPeekNextIrp(_In_ PIO_CSQ Csq, _In_ PIRP Irp, _In_ PVOID PeekContext)
{
    PLIST_ENTRY head, cur;
    UNREFERENCED_PARAMETER(Csq);
    UNREFERENCED_PARAMETER(PeekContext);

    head = &g_csq_list;
    cur  = (Irp == NULL) ? head->Flink : Irp->Tail.Overlay.ListEntry.Flink;
    if (cur == head) return NULL;
    return CONTAINING_RECORD(cur, IRP, Tail.Overlay.ListEntry);
}

static VOID CsqAcquireLock(_In_ PIO_CSQ Csq, _Out_ PKIRQL Irql)
{
    UNREFERENCED_PARAMETER(Csq);
    KeAcquireSpinLock(&g_csq_lock, Irql);
}

static VOID CsqReleaseLock(_In_ PIO_CSQ Csq, _In_ KIRQL Irql)
{
    UNREFERENCED_PARAMETER(Csq);
    KeReleaseSpinLock(&g_csq_lock, Irql);
}

static VOID CsqCompleteCanceledIrp(_In_ PIO_CSQ Csq, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(Csq);
    Irp->IoStatus.Status      = STATUS_CANCELLED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

/* ---- public API ---- */

NTSTATUS EventQueueInit(VOID)
{
    NTSTATUS status;

    KeInitializeSpinLock(&g_evt_lock);
    InitializeListHead(&g_evt_queue);
    g_evt_count = 0;

    KeInitializeSpinLock(&g_csq_lock);
    InitializeListHead(&g_csq_list);

    status = IoCsqInitialize(
        &g_csq,
        CsqInsertIrp,
        CsqRemoveIrp,
        CsqPeekNextIrp,
        CsqAcquireLock,
        CsqReleaseLock,
        CsqCompleteCanceledIrp);

    return status;
}

VOID EventQueueDestroy(VOID)
{
    PIRP        irp;
    KIRQL       irql;
    LIST_ENTRY  drain;
    PLIST_ENTRY le;

    /* Cancel everything pending. */
    while ((irp = IoCsqRemoveNextIrp(&g_csq, NULL)) != NULL)
    {
        irp->IoStatus.Status      = STATUS_CANCELLED;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
    }

    /* Drain queued events. */
    InitializeListHead(&drain);
    KeAcquireSpinLock(&g_evt_lock, &irql);
    while (!IsListEmpty(&g_evt_queue))
    {
        le = RemoveHeadList(&g_evt_queue);
        InsertTailList(&drain, le);
    }
    g_evt_count = 0;
    KeReleaseSpinLock(&g_evt_lock, irql);

    while (!IsListEmpty(&drain))
    {
        PAPIMON_EVENT_NODE node;
        le   = RemoveHeadList(&drain);
        node = CONTAINING_RECORD(le, APIMON_EVENT_NODE, link);
        ExFreePoolWithTag(node, APIMON_TAG);
    }
}

static VOID FillIrpFromNode(PIRP Irp, PAPIMON_EVENT_NODE node, PULONG_PTR pInfo)
{
    PIO_STACK_LOCATION s = IoGetCurrentIrpStackLocation(Irp);
    ULONG outLen = s->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG total  = sizeof(APIMON_EVENT_HEADER) + node->payload_size;

    if (outLen < total)
    {
        Irp->IoStatus.Status      = STATUS_BUFFER_TOO_SMALL;
        Irp->IoStatus.Information = 0;
        if (pInfo) *pInfo = 0;
        return;
    }

    /* Copy header + text. payload[] in the node already starts with header
     * shape, but we keep the canonical layout: write header, then text bytes. */
    {
        PUCHAR dst = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
        RtlCopyMemory(dst, &node->header, sizeof(APIMON_EVENT_HEADER));
        RtlCopyMemory(dst + sizeof(APIMON_EVENT_HEADER), node->payload, node->payload_size);
    }

    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = total;
    if (pInfo) *pInfo = total;
}

NTSTATUS EventTryDequeueIntoIrp(PIRP Irp, PULONG_PTR Information)
{
    KIRQL              irql;
    PAPIMON_EVENT_NODE node = NULL;

    KeAcquireSpinLock(&g_evt_lock, &irql);
    if (!IsListEmpty(&g_evt_queue))
    {
        PLIST_ENTRY le = RemoveHeadList(&g_evt_queue);
        node = CONTAINING_RECORD(le, APIMON_EVENT_NODE, link);
        g_evt_count--;
    }
    KeReleaseSpinLock(&g_evt_lock, irql);

    if (node == NULL)
        return STATUS_PENDING;     /* caller should park the IRP in CSQ */

    FillIrpFromNode(Irp, node, Information);
    {
        NTSTATUS s = Irp->IoStatus.Status;
        ExFreePoolWithTag(node, APIMON_TAG);
        return s;
    }
}

VOID EventInsertPendingIrp(PIRP Irp)
{
    IoMarkIrpPending(Irp);
    IoCsqInsertIrp(&g_csq, Irp, NULL);
}

VOID EventTryDeliverPending(VOID)
{
    /* Wake-up path: try to pair the head of g_evt_queue with the head of CSQ. */
    for (;;)
    {
        PIRP                irp;
        KIRQL               irql;
        PAPIMON_EVENT_NODE  node = NULL;

        irp = IoCsqRemoveNextIrp(&g_csq, NULL);
        if (irp == NULL) return;

        KeAcquireSpinLock(&g_evt_lock, &irql);
        if (!IsListEmpty(&g_evt_queue))
        {
            PLIST_ENTRY le = RemoveHeadList(&g_evt_queue);
            node = CONTAINING_RECORD(le, APIMON_EVENT_NODE, link);
            g_evt_count--;
        }
        KeReleaseSpinLock(&g_evt_lock, irql);

        if (node == NULL)
        {
            /* No event after all; put IRP back. */
            IoCsqInsertIrp(&g_csq, irp, NULL);
            return;
        }

        FillIrpFromNode(irp, node, NULL);
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        ExFreePoolWithTag(node, APIMON_TAG);
    }
}

NTSTATUS EventEnqueueText(UINT32 source, UINT32 subcategory,
                          ULONG pid, ULONG tid, PCWSTR text)
{
    SIZE_T              textLenW;
    SIZE_T              payloadBytes;
    SIZE_T              nodeBytes;
    PAPIMON_EVENT_NODE  node;
    LARGE_INTEGER       qpc;
    KIRQL               irql;
    BOOLEAN             dropped = FALSE;

    if (text == NULL) return STATUS_INVALID_PARAMETER;

    textLenW = wcslen(text);
    if (textLenW > APIMON_MAX_TEXT_WCHARS - 1) textLenW = APIMON_MAX_TEXT_WCHARS - 1;

    payloadBytes = textLenW * sizeof(WCHAR);
    nodeBytes    = FIELD_OFFSET(APIMON_EVENT_NODE, payload) + payloadBytes;

    /* ExAllocatePool2 is the modern API (Windows 10 v2004+); zero-inits memory by default. */
    node = (PAPIMON_EVENT_NODE)ExAllocatePool2(POOL_FLAG_NON_PAGED, nodeBytes, APIMON_TAG);
    if (node == NULL) return STATUS_INSUFFICIENT_RESOURCES;

    qpc = KeQueryPerformanceCounter(NULL);

    node->payload_size       = (UINT32)payloadBytes;
    node->header.total_size  = (UINT32)(sizeof(APIMON_EVENT_HEADER) + payloadBytes);
    node->header.pid         = pid;
    node->header.tid         = tid;
    node->header.timestamp_qpc = (UINT64)qpc.QuadPart;
    node->header.source      = source;
    node->header.subcategory = subcategory;
    node->header.text_offset = (UINT32)sizeof(APIMON_EVENT_HEADER);
    node->header.text_length = (UINT32)textLenW;
    if (payloadBytes) RtlCopyMemory(node->payload, text, payloadBytes);

    KeAcquireSpinLock(&g_evt_lock, &irql);
    if (g_evt_count >= MAX_QUEUED_EVENTS)
    {
        dropped = TRUE;
    }
    else
    {
        InsertTailList(&g_evt_queue, &node->link);
        g_evt_count++;
    }
    KeReleaseSpinLock(&g_evt_lock, irql);

    if (dropped)
    {
        ExFreePoolWithTag(node, APIMON_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Try to wake any user-mode worker that's already waiting. */
    EventTryDeliverPending();
    return STATUS_SUCCESS;
}
