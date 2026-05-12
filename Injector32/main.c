/*
 * Injector32.exe - tiny x86 helper that the (x64) Loader uses to inject
 * APIHook32.dll into a 32-bit (WoW64) target. Args: <pid> <full_dll_path>
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <strsafe.h>

static int Fail(LPCSTR msg)
{
    DWORD err = GetLastError();
    HANDLE hErr = GetStdHandle(STD_ERROR_HANDLE);
    char buf[256];
    DWORD written;
    StringCchPrintfA(buf, ARRAYSIZE(buf), "Injector32: %s (GLE=%lu)\r\n", msg, err);
    WriteFile(hErr, buf, lstrlenA(buf), &written, NULL);
    return 1;
}

static DWORD ParseDword(LPCWSTR s)
{
    DWORD v = 0;
    while (*s >= L'0' && *s <= L'9') { v = v * 10 + (DWORD)(*s - L'0'); s++; }
    return v;
}

int wmain(int argc, wchar_t **argv)
{
    DWORD   pid;
    LPCWSTR dllPath;
    SIZE_T  cbPath;
    HANDLE  hProc;
    LPVOID  remoteBuf;
    SIZE_T  written = 0;
    HMODULE hKernel32;
    LPVOID  pLoadLibraryW;
    HANDLE  hThread;

    if (argc < 3) return Fail("usage: Injector32.exe <pid> <full-path-to-dll>");

    pid     = ParseDword(argv[1]);
    dllPath = argv[2];
    if (pid == 0) return Fail("bad pid");

    cbPath = (lstrlenW(dllPath) + 1) * sizeof(WCHAR);

    hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                        PROCESS_VM_WRITE | PROCESS_VM_READ |
                        PROCESS_QUERY_INFORMATION,
                        FALSE, pid);
    if (hProc == NULL) return Fail("OpenProcess failed");

    remoteBuf = VirtualAllocEx(hProc, NULL, cbPath, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remoteBuf == NULL) { CloseHandle(hProc); return Fail("VirtualAllocEx failed"); }

    if (!WriteProcessMemory(hProc, remoteBuf, dllPath, cbPath, &written) || written != cbPath) {
        VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return Fail("WriteProcessMemory failed");
    }

    hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (hKernel32 == NULL) { VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE); CloseHandle(hProc); return Fail("GetModuleHandle(kernel32) failed"); }
    pLoadLibraryW = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryW");
    if (pLoadLibraryW == NULL) { VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE); CloseHandle(hProc); return Fail("GetProcAddress(LoadLibraryW) failed"); }

    hThread = CreateRemoteThread(hProc, NULL, 0,
                                 (LPTHREAD_START_ROUTINE)pLoadLibraryW,
                                 remoteBuf, 0, NULL);
    if (hThread == NULL) {
        VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return Fail("CreateRemoteThread failed");
    }

    if (WaitForSingleObject(hThread, 5000) != WAIT_OBJECT_0) {
        CloseHandle(hThread);
        VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return Fail("Remote LoadLibraryW did not finish in time");
    }

    {
        DWORD rc = 0;
        GetExitCodeThread(hThread, &rc);
        CloseHandle(hThread);
        VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProc);
        if (rc == 0) return Fail("Remote LoadLibraryW returned NULL (DLL failed to load)");
    }
    return 0;
}
