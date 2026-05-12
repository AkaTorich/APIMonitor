/*
 * driver.c - DriverEntry / Unload, device creation, dispatch wiring.
 *
 * The whole driver is a passive "tap" - it registers Microsoft's public
 * notification callbacks (PsSetCreate*, PsSetLoadImage*) and feeds events
 * to user-mode through an inverted-call IOCTL.
 */
#include "driver.h"

PDEVICE_OBJECT g_DeviceObject = NULL;
UNICODE_STRING g_NtName  = RTL_CONSTANT_STRING(APIMON_DEVICE_NT_NAME);
UNICODE_STRING g_DosName = RTL_CONSTANT_STRING(APIMON_DEVICE_DOS_NAME);

DRIVER_UNLOAD                DriverUnload;
DRIVER_DISPATCH              DispatchDeviceControl;
DRIVER_DISPATCH              DispatchCreateClose;
DRIVER_DISPATCH              DispatchCleanup;

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    /* PING-TEST: each failing path returns a UNIQUE NTSTATUS so the sc.exe
     * Win32 error code maps back to a specific step:
     *      sc 1450 (NO_SYSTEM_RESOURCES)   -> IoCreateDeviceSecure failed
     *      sc    6 (INVALID_HANDLE)        -> IoCreateSymbolicLink failed
     *      sc   50 (NOT_SUPPORTED)         -> EventQueueInit failed
     *      sc 1168 (NOT_FOUND)             -> CbProcessInstall failed
     *      sc    2 (FILE_NOT_FOUND)        -> CbImageInstall failed
     *      sc    0 / no error              -> all good (running)
     */
    {
        UNICODE_STRING sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
        const GUID guid = { 0x44CF1A37, 0x7A88, 0x4F49,
                            { 0xB0,0x4D,0x12,0x6F,0x33,0x77,0x88,0xAA } };
        status = IoCreateDeviceSecure(
            DriverObject, 0, &g_NtName,
            FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE,
            &sddl, (LPCGUID)&guid, &g_DeviceObject);
    }
    if (!NT_SUCCESS(status)) return STATUS_INSUFFICIENT_RESOURCES; /* sc 1450 */

    g_DeviceObject->Flags |= DO_BUFFERED_IO;

    status = IoCreateSymbolicLink(&g_DosName, &g_NtName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return STATUS_INVALID_HANDLE; /* sc 6 */
    }

    DriverObject->DriverUnload                          = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE]          = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]           = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP]         = DispatchCleanup;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]  = DispatchDeviceControl;

    TargetInit();

    status = EventQueueInit();
    if (!NT_SUCCESS(status)) {
        IoDeleteSymbolicLink(&g_DosName);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return STATUS_NOT_IMPLEMENTED; /* sc 50 */
    }

    status = CbProcessInstall();
    if (!NT_SUCCESS(status)) {
        EventQueueDestroy();
        IoDeleteSymbolicLink(&g_DosName);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return STATUS_NOT_FOUND; /* sc 1168 */
    }

    status = CbImageInstall();
    if (!NT_SUCCESS(status)) {
        CbProcessUninstall();
        EventQueueDestroy();
        IoDeleteSymbolicLink(&g_DosName);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return STATUS_OBJECT_NAME_NOT_FOUND; /* sc 2 */
    }

    return STATUS_SUCCESS;
}

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    /* Order matters: stop generating events first, then drain queue, then drop device. */
    CbImageUninstall();
    CbProcessUninstall();
    EventQueueDestroy();

    if (g_DeviceObject != NULL)
    {
        IoDeleteSymbolicLink(&g_DosName);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }
}

NTSTATUS DispatchCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DispatchCleanup(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    /* User-mode handle is going away. Cancel any IRPs they had outstanding so
     * the inverted-call worker thread doesn't dangle. The CSQ cancel routine
     * does the actual completion. */
    {
        PFILE_OBJECT fileObj = IoGetCurrentIrpStackLocation(Irp)->FileObject;
        UNREFERENCED_PARAMETER(fileObj);
        /* Our CSQ matches by FILE_OBJECT inside the cancel context; see ioctl.c. */
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}
