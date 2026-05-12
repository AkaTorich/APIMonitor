/*
 * driver.h - shared driver-internal types/prototypes.
 */
#ifndef APIMON_DRIVER_H
#define APIMON_DRIVER_H

#include <ntifs.h>
#include <wdmsec.h>
#include "../apimon_proto.h"

#define APIMON_TAG  'mAPI'    /* 'IPAm' in memory */

/* Maximum number of PIDs we track at once (target + descendants). */
#define APIMON_MAX_PIDS  256

/* Single queued event (kernel-side allocation, non-paged). */
typedef struct _APIMON_EVENT_NODE {
    LIST_ENTRY            link;
    UINT32                payload_size;     /* bytes following the header in payload[] */
    APIMON_EVENT_HEADER   header;
    /* WCHAR text[] follows immediately after header in payload */
    UCHAR                 payload[1];       /* variable size */
} APIMON_EVENT_NODE, *PAPIMON_EVENT_NODE;

/* event_queue.c */
NTSTATUS EventQueueInit(VOID);
VOID     EventQueueDestroy(VOID);
NTSTATUS EventEnqueueText(UINT32 source, UINT32 subcategory,
                          ULONG pid, ULONG tid, PCWSTR text);
VOID     EventTryDeliverPending(VOID);
NTSTATUS EventTryDequeueIntoIrp(PIRP Irp, PULONG_PTR Information);
VOID     EventInsertPendingIrp(PIRP Irp);

/* target.c */
VOID    TargetInit(VOID);
VOID    TargetSet(ULONG pid);
VOID    TargetClear(VOID);
BOOLEAN TargetContains(ULONG pid);
VOID    TargetMaybeAddChild(ULONG parentPid, ULONG childPid);
VOID    TargetRemove(ULONG pid);

/* cb_proc.c */
NTSTATUS CbProcessInstall(VOID);
VOID     CbProcessUninstall(VOID);

/* cb_image.c */
NTSTATUS CbImageInstall(VOID);
VOID     CbImageUninstall(VOID);

/* ioctl.c */
NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DispatchCleanup(PDEVICE_OBJECT DeviceObject, PIRP Irp);

/* inject_apc.c - kernel APC injection for protected processes */
NTSTATUS InjectDllViaApc(ULONG pid, ULONG tid, PVOID llAddr, PCWSTR dllPath);

/* helper: format wide-string into a fixed buffer using RtlStringCb*. */

#endif
