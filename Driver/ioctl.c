/*
 * ioctl.c - IRP_MJ_DEVICE_CONTROL handler. Three opcodes:
 *   IOCTL_APIMON_SET_TARGET_PID  - input DWORD pid
 *   IOCTL_APIMON_CLEAR_TARGET    - no input
 *   IOCTL_APIMON_GET_EVENT       - inverted call; pends until an event is available.
 */
#include "driver.h"

NTSTATUS DispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION s = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS  status      = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    switch (s->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_APIMON_SET_TARGET_PID:
        if (s->Parameters.DeviceIoControl.InputBufferLength < sizeof(ULONG))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        {
            ULONG pid = *(PULONG)Irp->AssociatedIrp.SystemBuffer;
            TargetSet(pid);
        }
        status = STATUS_SUCCESS;
        break;

    case IOCTL_APIMON_CLEAR_TARGET:
        TargetClear();
        status = STATUS_SUCCESS;
        break;

    case IOCTL_APIMON_GET_EVENT:
        if (s->Parameters.DeviceIoControl.OutputBufferLength <
            sizeof(APIMON_EVENT_HEADER))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        status = EventTryDequeueIntoIrp(Irp, &information);
        if (status == STATUS_PENDING)
        {
            EventInsertPendingIrp(Irp);
            return STATUS_PENDING;     /* do not complete here */
        }
        break;

    case IOCTL_APIMON_INJECT_DLL:
        if (s->Parameters.DeviceIoControl.InputBufferLength < sizeof(APIMON_INJECT_REQ))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        {
            PAPIMON_INJECT_REQ req = (PAPIMON_INJECT_REQ)Irp->AssociatedIrp.SystemBuffer;
            req->dll_path[APIMON_MAX_DLL_PATH - 1] = L'\0';
            status = InjectDllViaApc(req->pid, req->tid,
                                     (PVOID)(ULONG_PTR)req->ll_addr, req->dll_path);
        }
        break;

    default:
        break;
    }

    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
