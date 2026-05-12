/*
 * apimon_proto.h - shared protocol between Hook DLL and the GUI.
 *
 * Transport: a per-target named file mapping
 *     "Local\apimon_ring_<pid>"
 * carrying a fixed-layout RingHeader followed by a circular array of
 * binary events. Hook side writes lock-free via InterlockedIncrement +
 * memcpy - no WinAPI call on the hot path. GUI side OpenFileMapping +
 * MapViewOfFile and polls.
 *
 * The slot table (mapping slot_id -> module + function name) lives at
 * the start of the same mapping so the GUI can decode events without
 * any out-of-band channel.
 */
#ifndef APIMON_PROTO_H
#define APIMON_PROTO_H

#ifdef _KERNEL_MODE
    #include <ntddk.h>
#else
    #include <windows.h>
    #include <winioctl.h>
#endif

/* Source field on events. Kept as enum for backward-compat with the C# side. */
#define APIMON_SOURCE_USER_API   0u
#define APIMON_SOURCE_USER_COM   1u
#define APIMON_SOURCE_KERNEL     2u
#define APIMON_SOURCE_WEIRD      3u   /* direct/indirect syscall detection */

#define APIMON_KSUB_PROC_CREATE  0u
#define APIMON_KSUB_PROC_EXIT    1u
#define APIMON_KSUB_IMAGE_LOAD   2u

/* Legacy event header (still used by Driver project; kept for build
 * compatibility - the user-mode side no longer reads from a pipe). */
#define APIMON_MAX_TEXT_WCHARS 1024
#pragma pack(push, 4)
typedef struct _APIMON_EVENT_HEADER {
    UINT32 total_size;
    UINT32 pid;
    UINT32 tid;
    UINT64 timestamp_qpc;
    UINT32 source;
    UINT32 subcategory;
    UINT32 text_offset;
    UINT32 text_length;
} APIMON_EVENT_HEADER, *PAPIMON_EVENT_HEADER;
#pragma pack(pop)
#define APIMON_PIPE_ENV_NAME    L"APIMON_PIPE"

/* Driver IOCTLs and inject request - unchanged. */
#define APIMON_DEVICE_TYPE           0x8000u
#define IOCTL_APIMON_SET_TARGET_PID  CTL_CODE(APIMON_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_APIMON_CLEAR_TARGET    CTL_CODE(APIMON_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_APIMON_GET_EVENT       CTL_CODE(APIMON_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_APIMON_INJECT_DLL      CTL_CODE(APIMON_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define APIMON_MAX_DLL_PATH 520

#pragma pack(push, 4)
typedef struct _APIMON_INJECT_REQ {
    UINT32 pid;
    UINT32 tid;
    UINT64 ll_addr;
    WCHAR  dll_path[APIMON_MAX_DLL_PATH];
} APIMON_INJECT_REQ, *PAPIMON_INJECT_REQ;
#pragma pack(pop)

/* --- shared-memory ring transport --- */

#define APIMON_RING_NAME_FMT     L"Local\\apimon_ring_%u"   /* format: pid */
#define APIMON_RING_CAPACITY     32768   /* must be a power of two */
#define APIMON_RING_MAX_SLOTS    32768
#define APIMON_RING_MOD_LEN      40
#define APIMON_RING_NAME_LEN     80

#pragma pack(push, 8)
typedef struct _APIMON_RING_SLOT {
    char module[APIMON_RING_MOD_LEN];
    char name  [APIMON_RING_NAME_LEN];
} APIMON_RING_SLOT;

typedef struct _APIMON_RING_EVENT {
    UINT64 ts_qpc;
    UINT32 pid;
    UINT32 tid;
    UINT32 slot_id;
    UINT32 source;
    UINT64 caller_addr;     /* return address from the trampoline's POV =
                               instruction right after the call in caller */
    UINT64 args[12];
} APIMON_RING_EVENT;

typedef struct _APIMON_RING_HEADER {
    UINT32 magic;            /* 'APIM' */
    UINT32 version;          /* 1 */
    UINT32 capacity;         /* APIMON_RING_CAPACITY */
    UINT32 max_slots;        /* APIMON_RING_MAX_SLOTS */
    /* Hook side increments write_seq atomically; reader keeps its own
     * read_seq locally. dropped_seq_floor is set if a writer wraps past
     * an unread reader (data lost) - GUI surfaces it. */
    volatile LONG write_seq;
    volatile LONG dropped_seq_floor;
    volatile LONG slot_count;
    UINT32 _pad;
    APIMON_RING_SLOT  slots[APIMON_RING_MAX_SLOTS];
    APIMON_RING_EVENT events[APIMON_RING_CAPACITY];
} APIMON_RING_HEADER;
#pragma pack(pop)

#define APIMON_RING_MAGIC   ((UINT32)'MIPA')   /* 'APIM' little-endian */

/* Naming */
#define APIMON_DEVICE_NT_NAME   L"\\Device\\APIMonitorDrv"
#define APIMON_DEVICE_DOS_NAME  L"\\DosDevices\\APIMonitorDrv"
#define APIMON_DEVICE_USER_PATH L"\\\\.\\APIMonitorDrv"
#define APIMON_SERVICE_NAME     L"APIMonitorDrv"

#endif /* APIMON_PROTO_H */
