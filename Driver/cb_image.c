/*
 * cb_image.c - PsSetLoadImageNotifyRoutine wiring.
 * Reports every image (DLL/EXE/SYS) loaded into a process we care about.
 * For SYSTEM-wide images (drivers) ProcessId is 0 - we ignore those.
 */
#include "driver.h"
#include <ntstrsafe.h>

static volatile LONG g_image_installed;

static VOID NTAPI ImageNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_     HANDLE          ProcessId,
    _In_     PIMAGE_INFO     ImageInfo)
{
    ULONG pid = HandleToULong(ProcessId);
    WCHAR line[APIMON_MAX_TEXT_WCHARS];

    if (pid == 0) return;
    if (!TargetContains(pid)) return;

    RtlStringCchPrintfW(line, ARRAYSIZE(line),
        L"IMAGE_LOAD image=\"%wZ\" base=0x%p size=0x%Ix kernel=%u",
        FullImageName ? FullImageName : NULL,
        ImageInfo->ImageBase,
        ImageInfo->ImageSize,
        ImageInfo->SystemModeImage ? 1u : 0u);

    EventEnqueueText(APIMON_SOURCE_KERNEL, APIMON_KSUB_IMAGE_LOAD,
                     pid, 0, line);
}

NTSTATUS CbImageInstall(VOID)
{
    NTSTATUS s = PsSetLoadImageNotifyRoutine(ImageNotify);
    if (NT_SUCCESS(s))
        InterlockedExchange(&g_image_installed, 1);
    return s;
}

VOID CbImageUninstall(VOID)
{
    if (InterlockedExchange(&g_image_installed, 0) == 1)
        PsRemoveLoadImageNotifyRoutine(ImageNotify);
}
