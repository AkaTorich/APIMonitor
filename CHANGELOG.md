# Changelog

## 2.0

Major update: return-value capture, remote monitoring through a relay, and a reworked interface.

### Return-value capture
- The hook now records not just the function call but also its **return value**.
- Each ring event gained `kind` (CALL / RET), `call_id`, and `ret_value` fields; the ring protocol was bumped to version 2.
- A call and its return are paired by `call_id`; the value is formatted by the return type from Win32Metadata (BOOL → TRUE/FALSE, integers → decimal, pointers/HANDLE → hex, void → blank).
- **x64**: the return is captured through a real wrapper function (`gate_x64.asm`, MASM) with proper unwind information — SEH and win32k callbacks are unaffected.
- **x86**: a wrapper that measures the stack cleanup; return capture is active but remains fragile inside win32k user-callback paths (see "Known limitations").
- Arguments and returns are logged from the very first call (no startup race).

### Remote monitoring (new ApimonRelay agent)
- **ApimonRelay.exe** — an agent to run on another machine / VM (requires administrator rights). It accepts a TCP request from the GUI, launches the target and injects the hook **on the remote machine**, reads the event ring, resolves caller modules, and streams decoded events back.
- The GUI gained a **remote mode**: a **Remote** checkbox plus **Host** and **Port** fields. With it enabled you enter the relay address and the target path (as it exists on the remote machine), and calls stream live into the same list.
- The relay builds into the shared `bin\$(Configuration)\` folder next to the hook DLLs and `Injector32.exe`.

### Remote file browser
- A **Browse VM...** button opens a window (in the same dark theme as the main window) that browses the remote machine's filesystem through the relay: navigate drives and folders, see only `.exe` files, pick the target with a double click.
- The relay protocol is now command-based (v2): `ListDir` (directory listing) and `Launch` (launch + stream).

### Interface
- The grid now keeps only **Function**, **Args**, and **Ret** columns (removed `#`, `PID`, `TID`, `Caller`).
- Columns size to their content (`Auto`), with a horizontal scrollbar at the bottom so long argument lists are fully visible.
- Added **search** over the `Function` / `Args` / `Ret` text (case-insensitive, live), combined with the source filter.
- Fixed maximize (`WM_GETMINMAXINFO`): the window fills the monitor's work area without clipped edges and without covering the taskbar, at any DPI.
- The **Remote** checkbox label is now visible (in the dark theme); disabled buttons are visually dimmed.

### Stability
- A hard retention cap on events in the GUI (old rows dropped on overflow) so a heavy target can't exhaust host memory.
- RET events no longer re-resolve the caller module (paired by `call_id`), reducing read overhead.

### Known limitations
- x86 return capture is unstable for apps that heavily use win32k user callbacks (some CRT-less GUI apps) — crashes are possible there; x64 is unaffected.
- In remote mode string arguments are not expanded (the relay has the target memory, not the GUI) — arguments show with types and hex values.
- In remote mode the kernel driver and the "weird syscall" detector are not used.

## 1.0

Initial version — a local WinAPI call tracer.

### Hooking engine
- **MinHook**-based inline hooks for **x86 and x64**.
- Hooks the exported functions of a set of system DLLs (kernel32, kernelbase, user32, gdi32, advapi32, ole32, ws2_32, wininet, crypt32, and others).
- Per-export trampoline: save registers → handler → write event → tail-jump into the original. Only the **call** was logged (function name + arguments + caller address), without the return value.

### Transport
- A per-process shared-memory ring `Local\apimon_ring_<pid>`: the hook writes events lock-free, the GUI polls. No kernel32 calls on the hot path (recursion protection through the hook itself).
- A slot table (slot_id → module + function name) in the same mapping so the GUI decodes events without a separate channel.

### Launch and injection
- `CreateProcess(SUSPENDED)` → inject the hook DLL → `ResumeThread`.
- User-mode injection (`VirtualAllocEx` + `CreateRemoteThread` on `LoadLibraryW`); for x86 via the `Injector32.exe` helper.
- Optional **kernel driver** `APIMonitorDrv.sys`: fallback APC injection plus process/image callbacks for protected / PPL processes.

### GUI (WPF)
- Event grid with `#`, `PID`, `TID`, `Function`, `Args`, `Ret` (empty), `Caller` columns.
- Argument formatting via **Win32Metadata** (parameter types and names); reads strings from the target's memory (`LPCWSTR`/`LPSTR` → text).
- Caller-module resolution from the return address and noise filtering of system-internal calls (System32/SysWOW64/WinSxS, CRT).
- Source filter (All / User-mode API / User-mode COM), a Clear button, a memory watchdog.
- "Weird syscall" detector via ETW (`Microsoft-Windows-Kernel-Audit-API-Calls`) — flags direct/indirect syscalls.
- A "y2k cybersec terminal" look (dark theme, phosphor green).
