/*
 * iat_hook.c - inline-hook engine on top of MinHook.
 *
 * One slot per hooked export. MinHook points each API at a tiny per-slot
 * stub that loads slot_id and jumps to a shared wrapper gate (GateX86 here
 * for x86, ApimonGateX64 in gate_x64.asm for x64). The gate logs the CALL,
 * calls the original via a real nested CALL, captures the return value,
 * optionally logs the RET, and returns - so call/return pairing is exact
 * and SEH/callbacks are unaffected (no return-address hijacking).
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
#define APIMON_TRAMPOLINE_SIZE 128
#else
#define APIMON_TRAMPOLINE_SIZE 96
#endif

typedef struct _APIMON_TRAMPOLINE {
    BYTE code[APIMON_TRAMPOLINE_SIZE];
} APIMON_TRAMPOLINE;

static APIMON_SLOT        *g_slots         = NULL;
static APIMON_TRAMPOLINE  *g_trampolines   = NULL;
static volatile LONG       g_slot_count    = 0;

/*
 * Return-value capture via a real wrapper frame (NOT return-address
 * hijacking - that breaks x64 table-based SEH unwinding and desyncs across
 * win32k/WOW64 callbacks, which crashed every target).
 *
 * MinHook points the API at a tiny per-slot stub that jumps to a shared
 * gate. The gate is a genuine function with a normal stack frame: it logs
 * the CALL, calls the original via the MinHook trampoline, captures the
 * return value, logs the RET, and returns to the caller. Because the call
 * to the original is a real nested CALL, the pairing is exact (no shadow
 * stack, no heuristics) and unwinding/callbacks behave normally.
 *
 *   x64: gate is MASM (gate_x64.asm) so the linker emits proper unwind
 *        info; it forwards rcx/rdx/r8/r9 plus a generous span of stack args.
 *   x86: gate is a naked wrapper below. stdcall cleans an unknown number of
 *        argument bytes, so instead of needing the arity up front we MEASURE
 *        how many bytes the original popped (ESP delta) and clean exactly
 *        that many on the way back - works for both stdcall and cdecl.
 */

/* The four helpers the gates call. Non-static so the x64 MASM gate can
 * link against them; the x86 naked gate calls them by name in the same
 * translation unit. */
ULONG_PTR GateLogCall(ULONG_PTR slot_id, ULONG_PTR *regs, ULONG_PTR *stack, ULONG_PTR caller_ret)
{
    if (g_in_init || g_log_disabled) return 0;

    if (g_tlsInHook != TLS_OUT_OF_INDEXES) {
        if (GuardGet(g_tlsInHook) != NULL) return 0;
        GuardSet(g_tlsInHook, (PVOID)(ULONG_PTR)1);
    }

    ULONG_PTR all[12];
#if defined(_WIN64)
    all[0] = regs[0]; all[1] = regs[1]; all[2] = regs[2]; all[3] = regs[3];
    for (int i = 0; i < 8; i++) all[4 + i] = stack[i];
#else
    (void)regs;
    for (int i = 0; i < 12; i++) all[i] = stack[i];
#endif

    UINT32 call_id = RingPushCall((UINT32)slot_id, caller_ret, all);

    if (g_tlsInHook != TLS_OUT_OF_INDEXES)
        GuardSet(g_tlsInHook, NULL);

    /* call_id 0 is valid; the gate distinguishes "skip" via GateWantRet. */
    return call_id;
}

int GateWantRet(ULONG_PTR slot_id)
{
    (void)slot_id;
    if (g_in_init || g_log_disabled) return 0;
    return 1;
}

void GateLogRet(ULONG_PTR slot_id, ULONG_PTR caller_ret, UINT32 call_id, ULONG_PTR retval)
{
    int had = 0;
    if (g_tlsInHook != TLS_OUT_OF_INDEXES) {
        if (GuardGet(g_tlsInHook) == NULL) {
            GuardSet(g_tlsInHook, (PVOID)(ULONG_PTR)1);
            had = 1;
        }
    }
    RingPushRet((UINT32)slot_id, caller_ret, call_id, retval);
    if (had)
        GuardSet(g_tlsInHook, NULL);
}

void *GateOrig(ULONG_PTR slot_id)
{
    return g_slots[slot_id].orig_addr;
}

#if defined(_WIN64)
/* The x64 gate lives in gate_x64.asm (MASM, so the linker emits proper
 * unwind info - essential for table-based SEH). The per-slot stub loads
 * slot_id into r10 and jumps to it. */
extern void ApimonGateX64(void);
#else
/*
 * x86 wrapper gate. Reached from the per-slot stub with EAX = slot_id and
 * the stack exactly as the API was called: [esp]=caller_ret, [esp+4..]=args.
 *
 * It builds a real EBP frame, logs the CALL, then:
 *   - if return capture isn't wanted: tail-jumps into the original with the
 *     stack untouched (pure log, zero return-path interference);
 *   - else: copies a generous span of argument bytes, calls the original as
 *     a genuine nested CALL, MEASURES how many bytes it popped (ESP delta -
 *     works for stdcall and cdecl alike), logs the RET with the captured
 *     EAX, then returns to the caller cleaning exactly that many bytes.
 *
 * No return-address hijack and no shadow stack, so SEH and win32k/WOW64
 * callbacks are completely unaffected.
 */
__declspec(naked) static void GateX86(void)
{
    __asm {
        ; eax = slot_id ; ecx/edx = caller's (fastcall/thiscall args!) ;
        ; [esp]=caller_ret, [esp+4..]=stack args
        push ebp
        mov  ebp, esp
        sub  esp, 24              ; [ebp-4]=slot [ebp-8]=call_id [ebp-12]=M
                                  ; [ebp-16]=retval [ebp-20]=ecx [ebp-24]=edx
        mov  dword ptr [ebp-4], eax
        mov  dword ptr [ebp-20], ecx   ; preserve fastcall ecx
        mov  dword ptr [ebp-24], edx   ; preserve fastcall edx
        push ebx                  ; [ebp-28] saved caller ebx
        push esi                  ; [ebp-32] saved caller esi
        push edi                  ; [ebp-36] saved caller edi

        ; --- GateLogCall(slot, regs, stack, caller_ret) ---
        ; 4 args. On x86 there are no register args, so regs == stack == &args.
        mov  eax, [ebp+4]
        push eax                  ; caller_ret (4th)
        lea  eax, [ebp+8]
        push eax                  ; stack = &args (3rd)
        push eax                  ; regs  = &args (2nd)
        push dword ptr [ebp-4]    ; slot  (1st)
        call GateLogCall
        add  esp, 16
        mov  [ebp-8], eax         ; call_id

        ; --- GateWantRet(slot) ---
        push dword ptr [ebp-4]
        call GateWantRet
        add  esp, 4
        test eax, eax
        jz   tail

        ; ===== capture path: copy args, call original, measure pop =====
        sub  esp, 128
        cld
        mov  edi, esp
        lea  esi, [ebp+8]
        mov  ecx, 32              ; copy up to 32 dword args (was 24)
        rep  movsd
        mov  ebx, esp             ; arg-copy base (nonvol; survives the call)

        push dword ptr [ebp-4]
        call GateOrig
        add  esp, 4               ; eax = original (MinHook trampoline); esp back to ebx

        mov  ecx, [ebp-20]        ; restore fastcall args for the original
        mov  edx, [ebp-24]
        call eax                  ; nested call; stdcall pops its args -> esp = ebx + M
        mov  [ebp-16], eax        ; captured return value

        mov  ecx, esp
        sub  ecx, ebx
        mov  [ebp-12], ecx        ; M = bytes the original popped

        ; --- GateLogRet(slot, caller_ret, call_id, retval) ---
        push dword ptr [ebp-16]
        push dword ptr [ebp-8]
        push dword ptr [ebp+4]
        push dword ptr [ebp-4]
        call GateLogRet
        add  esp, 16

        ; --- return to caller, cleaning M argument bytes ---
        mov  eax, [ebp-16]        ; retval -> eax
        mov  ecx, [ebp+4]         ; caller_ret
        mov  edx, [ebp-12]        ; M
        lea  edx, [ebp+edx+8]     ; final esp = ebp+8+M (== entry esp +4 +M)
        mov  ebx, [ebp-28]
        mov  esi, [ebp-32]
        mov  edi, [ebp-36]
        mov  ebp, [ebp]
        mov  esp, edx
        jmp  ecx

      tail:
        ; log-only: restore all registers (incl. fastcall ecx/edx) and
        ; tail-jump into the original, leaving the stack exactly as at entry.
        push dword ptr [ebp-4]
        call GateOrig
        add  esp, 4               ; eax = original
        mov  ebx, [ebp-28]
        mov  esi, [ebp-32]
        mov  edi, [ebp-36]
        mov  ecx, [ebp-20]        ; restore fastcall ecx
        mov  edx, [ebp-24]        ; restore fastcall edx
        mov  esp, ebp
        pop  ebp                  ; esp now -> caller_ret slot, stack as at entry
        jmp  eax                  ; eax holds orig; eax is not an input arg on x86
    }
}
#endif

#if defined(_WIN64)
/*
 * Per-slot stub: load slot_id into r10 (a volatile register, not an argument
 * register) and jump to the shared MASM gate. rcx/rdx/r8/r9 (args 1-4) and
 * the stack args are left exactly as the caller set them.
 */
static void GenerateTrampoline(BYTE *p, ULONG_PTR slot_id)
{
    /* mov r10, slot_id */
    *p++ = 0x49; *p++ = 0xBA;
    *(ULONGLONG *)p = (ULONGLONG)slot_id; p += 8;
    /* mov rax, ApimonGateX64 */
    *p++ = 0x48; *p++ = 0xB8;
    *(ULONGLONG *)p = (ULONGLONG)(ULONG_PTR)ApimonGateX64; p += 8;
    /* jmp rax */
    *p++ = 0xFF; *p++ = 0xE0;
}
#else
/*
 * Per-slot stub: load slot_id into eax and jump (rel32) to GateX86. Only
 * eax is touched - it is never an incoming argument register in any x86
 * calling convention, so ecx/edx (fastcall/thiscall args) reach the gate
 * intact. The original stack ([esp]=caller_ret, [esp+4..]=args) is left
 * untouched.
 */
static void GenerateTrampoline(BYTE *p, ULONG_PTR slot_id)
{
    BYTE *start = p;
    /* mov eax, slot_id */
    *p++ = 0xB8;
    *(ULONG *)p = (ULONG)slot_id; p += 4;
    /* jmp rel32 -> GateX86 */
    *p++ = 0xE9;
    *(LONG *)p = (LONG)((ULONG_PTR)GateX86 - ((ULONG_PTR)start + 10)); p += 4;
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
    /* Conservative core set - the recent extension to 44 DLLs caused
     * STATUS_FATAL_USER_CALLBACK_EXCEPTION on launch (a prolog in one of
     * the new DLLs MinHook can't relocate). Add modules back one by one
     * once the base set is verified to run cleanly. */
    L"kernel32.dll",  L"kernelbase.dll", L"user32.dll",   L"gdi32.dll",
    L"advapi32.dll",  L"ole32.dll",      L"oleaut32.dll", L"shell32.dll",
    L"shlwapi.dll",   L"ws2_32.dll",     L"wininet.dll",  L"winhttp.dll",
    L"crypt32.dll",   L"bcrypt.dll",     L"ncrypt.dll",   L"wintrust.dll",
    L"comctl32.dll",  L"comdlg32.dll",   L"iphlpapi.dll", L"dnsapi.dll",
    L"psapi.dll",     L"version.dll",    L"sspicli.dll",  L"secur32.dll",
    L"userenv.dll",   L"wtsapi32.dll",   L"mpr.dll",      L"netapi32.dll",
    L"imagehlp.dll",  L"dbghelp.dll",    L"urlmon.dll"
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
