using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using APIMonitor.Native;

namespace APIMonitor.Services
{
    /// <summary>
    /// Three-stage injection strategy:
    ///   1) Same-bitness user-mode (VirtualAllocEx + CreateRemoteThread).
    ///   2) For x86 (WoW64) targets - via Injector32.exe helper.
    ///   3) If (1)/(2) fail (PPL, mitigations, etc.) - kernel APC injection
    ///      through the driver (IOCTL_APIMON_INJECT_DLL).
    /// </summary>
    public static class Injector
    {
        public static void InjectInto(IntPtr hProcess, uint pid, uint tid, bool targetIs64Bit,
                                      string baseDir, DriverClient driver)
        {
            string dllName = targetIs64Bit ? "APIHook64.dll" : "APIHook32.dll";
            string dllPath = Path.Combine(baseDir, dllName);
            if (!File.Exists(dllPath))
                throw new FileNotFoundException(
                    "Hook DLL not found next to APIMonitor.exe: " + dllName, dllPath);

            // 1. Try user-mode first (cheapest).
            try
            {
                if (targetIs64Bit) InjectX64(hProcess, dllPath);
                else               InjectX86ViaHelper(pid, baseDir, dllPath);
                return;
            }
            catch (Exception userEx)
            {
                Debug.WriteLine("User-mode injection failed: " + userEx.Message);

                // 2. Fall back to kernel APC injection through the driver.
                if (driver != null && driver.IsOpen)
                {
                    try
                    {
                        ulong llAddr = ResolveLoadLibraryW();
                        driver.InjectDll(pid, tid, llAddr, dllPath);
                        return;
                    }
                    catch (Exception drvEx)
                    {
                        throw new InvalidOperationException(
                            "Both user-mode injection and kernel APC injection failed.\n" +
                            "User-mode: " + userEx.Message + "\n" +
                            "Driver: " + drvEx.Message);
                    }
                }
                throw;
            }
        }

        private static ulong ResolveLoadLibraryW()
        {
            // kernel32 is per-boot ASLR'd, not per-process - the address of LoadLibraryW
            // is the same in every process of the current session.
            IntPtr hKernel32 = NativeMethods.GetModuleHandleW("kernel32.dll");
            if (hKernel32 == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "GetModuleHandle(kernel32) failed");
            IntPtr p = NativeMethods.GetProcAddress(hKernel32, "LoadLibraryW");
            if (p == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "GetProcAddress(LoadLibraryW) failed");
            return (ulong)p.ToInt64();
        }

        private static void InjectX64(IntPtr hProcess, string dllPath)
        {
            byte[] pathBytes = Encoding.Unicode.GetBytes(dllPath + "\0");
            UIntPtr cb = new UIntPtr((uint)pathBytes.Length);

            IntPtr remoteBuf = NativeMethods.VirtualAllocEx(hProcess, IntPtr.Zero, cb,
                NativeMethods.MEM_COMMIT | NativeMethods.MEM_RESERVE,
                NativeMethods.PAGE_READWRITE);
            if (remoteBuf == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "VirtualAllocEx failed");

            try
            {
                if (!NativeMethods.WriteProcessMemory(hProcess, remoteBuf, pathBytes, cb, out _))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "WriteProcessMemory failed");

                IntPtr pLoadLibraryW = (IntPtr)(long)ResolveLoadLibraryW();

                IntPtr hRemoteThread = NativeMethods.CreateRemoteThread(
                    hProcess, IntPtr.Zero, UIntPtr.Zero,
                    pLoadLibraryW, remoteBuf, 0, out _);
                if (hRemoteThread == IntPtr.Zero)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateRemoteThread failed");

                try
                {
                    // Generous timeout: APIHook64.dll is ~11 MB and patches ~21K
                    // IAT slots in DllMain, which on a cold disk can easily run
                    // past the original 5 s.
                    uint waitRc = NativeMethods.WaitForSingleObject(hRemoteThread, 60000);
                    if (waitRc != NativeMethods.WAIT_OBJECT_0)
                        throw new InvalidOperationException(
                            "Remote LoadLibraryW thread did not finish in time (rc=" + waitRc + ")");
                }
                finally
                {
                    NativeMethods.CloseHandle(hRemoteThread);
                }
            }
            finally
            {
                NativeMethods.VirtualFreeEx(hProcess, remoteBuf, UIntPtr.Zero, NativeMethods.MEM_RELEASE);
            }
        }

        private static void InjectX86ViaHelper(uint pid, string baseDir, string dllPath)
        {
            string helper = Path.Combine(baseDir, "Injector32.exe");
            if (!File.Exists(helper))
                throw new FileNotFoundException("Injector32.exe not found next to APIMonitor.exe", helper);

            var psi = new ProcessStartInfo
            {
                FileName = helper,
                Arguments = pid + " \"" + dllPath + "\"",
                UseShellExecute = false,
                CreateNoWindow  = true,
                RedirectStandardOutput = true,
                RedirectStandardError  = true
            };

            using (var p = Process.Start(psi))
            {
                if (!p.WaitForExit(5000))
                {
                    try { p.Kill(); } catch { }
                    throw new InvalidOperationException("Injector32.exe timed out");
                }
                if (p.ExitCode != 0)
                {
                    string err = p.StandardError.ReadToEnd();
                    throw new InvalidOperationException(
                        "Injector32.exe failed with exit code " + p.ExitCode + ": " + err);
                }
            }
        }
    }
}
