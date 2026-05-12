/*
 * iat_hook.c - inline-hook engine on top of MinHook.
 *
 * One slot per hooked export. Per-slot trampoline saves arg registers,
 * calls CommonHandler(slot_id, args*), restores, tail-jmps to MinHook's
 * trampoline-back (which runs the original code).
 *
 * CommonHandler does ONLY:
 *   - in_init / log_disabled / TLS guard short-circuit
 *   - RingPush() - one InterlockedIncrement and a struct copy
 *   - clear guard
 * No formatting, no kernel32 call, no recursion path.
 */
#include "hook_common.h"
#include "log_client.h"
#include "imports.h"
#include "MinHook.h"
#include <intrin.h>

/*
 * Direct TLS slot access via TIB intrinsic. Going through g_imp.pTlsGetValue
 * would land in our own hook (kernel32!TlsGetValue is patched), recurse,
 * and stack-overflow before guard could ever be set. TEB.TlsSlots[i] is a
 * raw memory read - no call, no recursion.
 *
 *   x64: TEB at GS:[0x30], TlsSlots at TEB+0x1480 (64 slots * 8 bytes)
 *   x86: TEB at FS:[0x18], TlsSlots at TEB+0xE10  (64 slots * 4 bytes)
 *
 * Only valid for slot indices 0..63. TlsAlloc returns indices in this range
 * for almost every process; if it ever hands out a slot >= 64 we fall back
 * silently and the guard is bypassed (worst case: a few duplicate events,
 * never a crash).
 */
#if defined(_WIN64)
static __forceinline PVOID GuardGet(DWORD slot)
{
    if (slot >= 64) return NULL;
    PVOID *slots = (PVOID *)(__readgsqword(0x30) + 0x1480);
    return slots[slot];
}
static __forceinline void GuardSet(DWORD slot, PVOID v)
{
    if (slot >= 64) return;
    PVOID *slots = (PVOID *)(__readgsqword(0x30) + 0x1480);
    slots[slot] = v;
}
#else
static __forceinline PVOID GuardGet(DWORD slot)
{
    if (slot >= 64) return NULL;
    PVOID *slots = (PVOID *)(__readfsdword(0x18) + 0xE10);
    return slots[slot];
}
static __forceinline void GuardSet(DWORD slot, PVOID v)
{
    if (slot >= 64) return;
    PVOID *slots = (PVOID *)(__readfsdword(0x18) + 0xE10);
    slots[slot] = v;
}
#endif

#define APIMON_MAX_SLOTS  32768

typedef struct _APIMON_SLOT {
    PVOID  orig_addr;
} APIMON_SLOT;

#if defined(_WIN64)
#define APIMON_TRAMPOLINE_SIZE 96
#else
#define APIMON_TRAMPOLINE_SIZE 64
#endif

typedef struct _APIMON_TRAMPOLINE {
    BYTE code[APIMON_TRAMPOLINE_SIZE];
} APIMON_TRAMPOLINE;

static APIMON_SLOT        *g_slots         = NULL;
static APIMON_TRAMPOLINE  *g_trampolines   = NULL;
static volatile LONG       g_slot_count    = 0;

/*
 * regs/stackArgs as before. caller_retaddr = address right after the
 * `call` instruction in the calling module - lets the GUI map it back
 * to whichever DLL/exe initiated the WinAPI call.
 */
#if defined(_WIN64)
static void __fastcall
#else
static void __cdecl
#endif
CommonHandler(ULONG_PTR slot_id, ULONG_PTR *regs, ULONG_PTR *stackArgs, ULONG_PTR caller_retaddr)
{
    if (g_in_init) return;
    if (g_log_disabled) return;

    /* Drop events whose caller is in a "noise" module: our Hook DLL, the
     * C runtime, or any System32/SysWOW64/WinSxS DLL (system-to-system
     * internal traffic). Linear scan over <= 256 ranges is fine - the
     * trampoline path is already heavy. */
    {
        LONG n = g_noise_count;
        for (LONG i = 0; i < n; i++) {
            if (caller_retaddr >= g_noise_ranges[i].base &&
                caller_retaddr <  g_noise_ranges[i].end)
                return;
        }
    }

    if (g_tlsInHook != TLS_OUT_OF_INDEXES) {
        if (GuardGet(g_tlsInHook) != NULL) return;
        GuardSet(g_tlsInHook, (PVOID)(ULONG_PTR)1);
    }

    ULONG_PTR all[12];
#if defined(_WIN64)
    all[0] = regs[0];
    all[1] = regs[1];
    all[2] = regs[2];
    all[3] = regs[3];
    for (int i = 0; i < 8; i++) all[4 + i] = stackArgs[i];
#else
    (void)regs;
    for (int i = 0; i < 12; i++) all[i] = stackArgs[i];
#endif

    RingPush((UINT32)slot_id, caller_retaddr, all);

    if (g_tlsInHook != TLS_OUT_OF_INDEXES)
        GuardSet(g_tlsInHook, NULL);
}

#if defined(_WIN64)
/*
 * After 4 pushes (32 bytes), caller's return address sits at [rsp+32]
 * (it was at [rsp+0] on trampoline entry). Load it into r9 as the 4th
 * arg of CommonHandler. Stack args 5+ live at [rsp+72] (32 pushes + 8
 * retaddr + 32 caller-shadow).
 */
static void GenerateTrampoline(BYTE *p, ULONG_PTR slot_id)
{
    PVOID *orig_ptr = &g_slots[slot_id].orig_addr;

    /* push r9 / push r8 / push rdx / push rcx */
    *p++ = 0x41; *p++ = 0x51;
    *p++ = 0x41; *p++ = 0x50;
    *p++ = 0x52;
    *p++ = 0x51;

    /* mov rcx, slot_id */
    *p++ = 0x48; *p++ = 0xB9;
    *(ULONGLONG *)p = (ULONGLONG)slot_id; p += 8;

    /* mov rdx, rsp  -- ptr to saved [rcx,rdx,r8,r9] */
    *p++ = 0x48; *p++ = 0x89; *p++ = 0xE2;

    /* lea r8, [rsp + 72]  -- ptr to caller's stack args (arg5+) */
    *p++ = 0x4C; *p++ = 0x8D; *p++ = 0x44; *p++ = 0x24; *p++ = 0x48;

    /* mov r9, [rsp + 32]  -- caller return address (4th arg) */
    *p++ = 0x4C; *p++ = 0x8B; *p++ = 0x4C; *p++ = 0x24; *p++ = 0x20;

    /* sub rsp, 40  -- shadow space + 8-byte align */
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xEC; *p++ = 0x28;

    /* mov rax, CommonHandler */
    *p++ = 0x48; *p++ = 0xB8;
    *(ULONGLONG *)p = (ULONGLONG)(ULONG_PTR)CommonHandler; p += 8;

    /* call rax */
    *p++ = 0xFF; *p++ = 0xD0;

    /* add rsp, 40 */
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xC4; *p++ = 0x28;

    /* pop rcx / pop rdx / pop r8 / pop r9 */
    *p++ = 0x59;
    *p++ = 0x5A;
    *p++ = 0x41; *p++ = 0x58;
    *p++ = 0x41; *p++ = 0x59;

    /* mov rax, qword ptr [orig_ptr] */
    *p++ = 0x48; *p++ = 0xA1;
    *(ULONGLONG *)p = (ULONGLONG)(ULONG_PTR)orig_ptr; p += 8;

    /* jmp rax */
    *p++ = 0xFF; *p++ = 0xE0;
}
#else
/*
 * x86 cdecl. After pushad+pushfd ret_addr at [esp+36], caller args at
 * [esp+40]. cdecl push order is right-to-left: 4th arg (caller_retaddr)
 * pushed first, then stackArgs, then regs, then slot_id.
 */
static void GenerateTrampoline(BYTE *p, ULONG_PTR slot_id)
{
    PVOID *orig_ptr = &g_slots[slot_id].orig_addr;

    /* pushad ; pushfd */
    *p++ = 0x60;
    *p++ = 0x9C;

    /* mov eax, [esp+36]  -- caller return address */
    *p++ = 0x8B; *p++ = 0x44; *p++ = 0x24; *p++ = 0x24;
    /* push eax           -- 4th arg (caller_retaddr) */
    *p++ = 0x50;

    /* lea eax, [esp+44]  -- caller args (offset shifted by +4 from prior push) */
    *p++ = 0x8D; *p++ = 0x44; *p++ = 0x24; *p++ = 0x2C;
    /* push eax           -- 3rd arg (stackArgs) */
    *p++ = 0x50;
    /* push eax           -- 2nd arg (regs, same pointer) */
    *p++ = 0x50;
    /* push slot_id       -- 1st arg */
    *p++ = 0x68;
    *(ULONG *)p = (ULONG)slot_id; p += 4;

    /* mov eax, CommonHandler ; call eax */
    *p++ = 0xB8;
    *(ULONG *)p = (ULONG)(ULONG_PTR)CommonHandler; p += 4;
    *p++ = 0xFF; *p++ = 0xD0;

    /* add esp, 16 (cleanup 4 cdecl args) */
    *p++ = 0x83; *p++ = 0xC4; *p++ = 0x10;

    /* popfd ; popad */
    *p++ = 0x9D;
    *p++ = 0x61;

    /* jmp dword ptr [orig_ptr] */
    *p++ = 0xFF; *p++ = 0x25;
    *(ULONG *)p = (ULONG)(ULONG_PTR)orig_ptr; p += 4;
}
#endif

static DWORD HookModuleExports(HMODULE hMod, const char *modName)
{
    PIMAGE_DOS_HEADER       dos = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS       nt;
    PIMAGE_EXPORT_DIRECTORY exp;
    DWORD *names, *funcs;
    WORD  *ords;
    DWORD i, count = 0;

    if (dos == NULL || dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    nt = (PIMAGE_NT_HEADERS)((BYTE *)hMod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    if (nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) return 0;
    if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) return 0;

    exp   = (PIMAGE_EXPORT_DIRECTORY)((BYTE *)hMod +
              nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    names = (DWORD *)((BYTE *)hMod + exp->AddressOfNames);
    ords  = (WORD  *)((BYTE *)hMod + exp->AddressOfNameOrdinals);
    funcs = (DWORD *)((BYTE *)hMod + exp->AddressOfFunctions);

    DWORD expStart = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD expSize  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    for (i = 0; i < exp->NumberOfNames; i++) {
        const char *name = (const char *)((BYTE *)hMod + names[i]);
        DWORD       rva  = funcs[ords[i]];
        PVOID       addr;
        ULONG_PTR   slot_id;

        /* Skip forwarder exports. */
        if (rva >= expStart && rva < expStart + expSize) continue;

        addr = (PVOID)((BYTE *)hMod + rva);

        slot_id = (ULONG_PTR)InterlockedIncrement(&g_slot_count) - 1;
        if (slot_id >= APIMON_MAX_SLOTS) {
            InterlockedDecrement(&g_slot_count);
            return count;
        }

        g_slots[slot_id].orig_addr = NULL;
        RingRegisterSlot((UINT32)slot_id, modName, name);

        GenerateTrampoline(g_trampolines[slot_id].code, slot_id);

        if (MH_CreateHook(addr, g_trampolines[slot_id].code,
                          (LPVOID *)&g_slots[slot_id].orig_addr) != MH_OK) {
            continue;
        }
        count++;
    }
    return count;
}

static const wchar_t *kSystemModules[] = {
    /* core */
    L"kernel32.dll",  L"kernelbase.dll", L"user32.dll",   L"gdi32.dll",
    L"advapi32.dll",
    /* COM/OLE */
    L"ole32.dll",     L"oleaut32.dll",   L"combase.dll",
    /* shell */
    L"shell32.dll",   L"shlwapi.dll",    L"shcore.dll",
    L"comctl32.dll",  L"comdlg32.dll",
    /* network */
    L"ws2_32.dll",    L"wininet.dll",    L"winhttp.dll",  L"urlmon.dll",
    L"iphlpapi.dll",  L"dnsapi.dll",     L"mpr.dll",      L"netapi32.dll",
    L"wlanapi.dll",   L"fwpuclnt.dll",
    /* crypto / security */
    L"crypt32.dll",   L"bcrypt.dll",     L"ncrypt.dll",   L"wintrust.dll",
    L"sspicli.dll",   L"secur32.dll",
    /* process / debug / system */
    L"psapi.dll",     L"version.dll",    L"userenv.dll",  L"wtsapi32.dll",
    L"imagehlp.dll",  L"dbghelp.dll",    L"pdh.dll",      L"fltlib.dll",
    L"profapi.dll",
    /* RPC */
    L"rpcrt4.dll",
    /* Active Directory */
    L"ntdsapi.dll",
    /* Event Log / Scheduler */
    L"wevtapi.dll",   L"taskschd.dll",
    /* UI */
    L"dwmapi.dll",    L"uxtheme.dll"
};

DWORD HooksInstall(void)
{
    DWORD totalHooked = 0;
    size_t i;

    if (g_trampolines == NULL) {
        g_trampolines = (APIMON_TRAMPOLINE *)VirtualAlloc(NULL,
            APIMON_MAX_SLOTS * sizeof(APIMON_TRAMPOLINE),
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (g_trampolines == NULL) return 0;
    }
    if (g_slots == NULL) {
        g_slots = (APIMON_SLOT *)g_imp.pHeapAlloc(g_hHeap, HEAP_ZERO_MEMORY,
            APIMON_MAX_SLOTS * sizeof(APIMON_SLOT));
        if (g_slots == NULL) return 0;
    }

    if (MH_Initialize() != MH_OK) return 0;

    for (i = 0; i < sizeof(kSystemModules) / sizeof(kSystemModules[0]); i++) {
        HMODULE hMod = g_imp.pGetModuleHandleW(kSystemModules[i]);
        if (hMod == NULL) continue;

        char ansiName[40];
        int  k;
        for (k = 0; kSystemModules[i][k] && k < 39; k++)
            ansiName[k] = (char)kSystemModules[i][k];
        ansiName[k] = '\0';

        totalHooked += HookModuleExports(hMod, ansiName);
    }

    /* Hooks created but NOT enabled. HooksEnable() does that, after the
     * loader has released its lock (called from DLL_THREAD_ATTACH). */
    return totalHooked;
}

void HooksEnable(void)
{
    MH_EnableHook(MH_ALL_HOOKS);
}
