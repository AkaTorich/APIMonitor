/*
 * log_client.c - shared-memory ring transport.
 *
 * No file/pipe logging anywhere. RingPush is the only hot-path function;
 * it does InterlockedIncrement + a fixed-size struct copy, nothing else.
 * Thread-id is read straight from the TEB via a GS/FS-relative intrinsic
 * so even GetCurrentThreadId stays out of the path.
 */
#include "hook_common.h"
#include "log_client.h"
#include "imports.h"
#include <intrin.h>
#include <winnt.h>

HANDLE        g_hHeap        = NULL;
volatile LONG g_log_disabled = 1;
volatile LONG g_in_init      = 1;
DWORD         g_tlsInHook    = TLS_OUT_OF_INDEXES;

static HANDLE              g_hMap = NULL;
static APIMON_RING_HEADER *g_ring = NULL;
static DWORD               g_pid  = 0;

/* TEB.ClientId.UniqueThread offset:
 *   x86: TEB at FS:[0x18], ClientId.UniqueThread at TEB+0x24
 *   x64: TEB at GS:[0x30], ClientId.UniqueThread at TEB+0x48
 */
static __forceinline DWORD CurrentTidFromTeb(void)
{
#if defined(_WIN64)
    return (DWORD)__readgsqword(0x48);
#else
    return (DWORD)__readfsdword(0x24);
#endif
}

BOOL RingInit(void)
{
    WCHAR  name[64];

    if (g_hHeap == NULL) {
        g_hHeap = g_imp.pHeapCreate(0, 0, 0);
        if (g_hHeap == NULL) return FALSE;
    }
    if (g_tlsInHook == TLS_OUT_OF_INDEXES) {
        g_tlsInHook = g_imp.pTlsAlloc();
        if (g_tlsInHook == TLS_OUT_OF_INDEXES) return FALSE;
    }

    g_pid = g_imp.pGetCurrentProcessId();

    if (FAILED(StringCchPrintfW(name, ARRAYSIZE(name), APIMON_RING_NAME_FMT, g_pid)))
        return FALSE;

    SIZE_T mapSize = sizeof(APIMON_RING_HEADER);

    g_hMap = g_imp.pCreateFileMappingW(INVALID_HANDLE_VALUE, NULL,
        PAGE_READWRITE, (DWORD)((ULONGLONG)mapSize >> 32), (DWORD)(mapSize & 0xFFFFFFFF), name);
    if (g_hMap == NULL) return FALSE;

    g_ring = (APIMON_RING_HEADER *)g_imp.pMapViewOfFile(
        g_hMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (g_ring == NULL) {
        g_imp.pCloseHandle(g_hMap);
        g_hMap = NULL;
        return FALSE;
    }

    if (g_ring->magic != APIMON_RING_MAGIC) {
        g_ring->magic              = APIMON_RING_MAGIC;
        g_ring->version            = 1;
        g_ring->capacity           = APIMON_RING_CAPACITY;
        g_ring->max_slots          = APIMON_RING_MAX_SLOTS;
        g_ring->write_seq          = 0;
        g_ring->slot_count         = 0;
        g_ring->dropped_seq_floor  = 0;
    }
    return TRUE;
}

void RingShutdown(void)
{
    InterlockedExchange(&g_log_disabled, 1);
    if (g_ring != NULL) {
        g_imp.pUnmapViewOfFile(g_ring);
        g_ring = NULL;
    }
    if (g_hMap != NULL) {
        g_imp.pCloseHandle(g_hMap);
        g_hMap = NULL;
    }
}

void RingRegisterSlot(UINT32 slot_id, const char *module, const char *name)
{
    if (g_ring == NULL || slot_id >= APIMON_RING_MAX_SLOTS) return;
    APIMON_RING_SLOT *s = &g_ring->slots[slot_id];

    int i;
    for (i = 0; i < APIMON_RING_MOD_LEN - 1 && module[i]; i++) s->module[i] = module[i];
    s->module[i] = '\0';
    for (i = 0; i < APIMON_RING_NAME_LEN - 1 && name[i]; i++) s->name[i] = name[i];
    s->name[i] = '\0';

    LONG cur;
    do {
        cur = g_ring->slot_count;
        if ((LONG)(slot_id + 1) <= cur) break;
    } while (InterlockedCompareExchange(&g_ring->slot_count, (LONG)(slot_id + 1), cur) != cur);
}

void RingPush(UINT32 slot_id, ULONG_PTR caller_addr, const ULONG_PTR *args12)
{
    if (g_ring == NULL) return;

    LONG seq = InterlockedIncrement(&g_ring->write_seq) - 1;
    UINT32 idx = (UINT32)seq & (APIMON_RING_CAPACITY - 1);

    APIMON_RING_EVENT *e = &g_ring->events[idx];
    e->ts_qpc       = (UINT64)__rdtsc();
    e->pid          = g_pid;
    e->tid          = CurrentTidFromTeb();
    e->slot_id      = slot_id;
    e->source       = APIMON_SOURCE_USER_API;
    e->caller_addr  = (UINT64)caller_addr;
    for (int i = 0; i < 12; i++) e->args[i] = (UINT64)args12[i];
}
