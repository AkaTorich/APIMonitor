using System;
using System.Collections;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using APIMonitor.Native;

namespace APIMonitor.Services
{
    /// <summary>
    /// Order: CreateProcess(SUSPENDED) -> driver.SetTargetPid -> inject Hook DLL -> ResumeThread.
    /// Injection tries user-mode first; falls back to kernel APC via the driver
    /// for protected / mitigation-locked targets.
    /// </summary>
    public sealed class Launcher : IDisposable
    {
        public uint   Pid           { get; private set; }
        public uint   Tid           { get; private set; }
        public IntPtr ProcessHandle { get; private set; }
        public IntPtr ThreadHandle  { get; private set; }
        public bool   TargetIs64Bit { get; private set; }

        private readonly string       _baseDir;
        private readonly DriverClient _driver;
        private readonly string       _pipeName;

        public Launcher(string baseDir, DriverClient driver, string pipeName)
        {
            _baseDir  = baseDir;
            _driver   = driver;
            _pipeName = pipeName;
        }

        public void Launch(string targetPath)
        {
            if (string.IsNullOrWhiteSpace(targetPath))
                throw new ArgumentException("Target path is empty");
            if (!File.Exists(targetPath))
                throw new FileNotFoundException("Target executable not found: " + targetPath);

            if (!NativeMethods.GetBinaryTypeW(targetPath, out uint binType))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "GetBinaryType failed");
            TargetIs64Bit = (binType == NativeMethods.SCS_64BIT_BINARY);

            byte[] envBlock = BuildEnvironmentBlock(_pipeName);

            var si = new NativeMethods.STARTUPINFO();
            si.cb = (uint)Marshal.SizeOf(typeof(NativeMethods.STARTUPINFO));
            NativeMethods.PROCESS_INFORMATION pi;

            string cmd = "\"" + targetPath + "\"";
            string workDir = Path.GetDirectoryName(targetPath);
            if (string.IsNullOrEmpty(workDir)) workDir = null;

            GCHandle envPin = GCHandle.Alloc(envBlock, GCHandleType.Pinned);
            try
            {
                bool ok = NativeMethods.CreateProcessW(
                    null, cmd,
                    IntPtr.Zero, IntPtr.Zero, false,
                    NativeMethods.CREATE_SUSPENDED | NativeMethods.CREATE_UNICODE_ENVIRONMENT,
                    envPin.AddrOfPinnedObject(),
                    workDir, ref si, out pi);
                if (!ok)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcess failed");
            }
            finally
            {
                envPin.Free();
            }

            Pid           = pi.dwProcessId;
            Tid           = pi.dwThreadId;
            ProcessHandle = pi.hProcess;
            ThreadHandle  = pi.hThread;

            try
            {
                if (_driver != null && _driver.IsOpen)
                    _driver.SetTargetPid(Pid);

                Injector.InjectInto(ProcessHandle, Pid, Tid, TargetIs64Bit, _baseDir, _driver);

                if (NativeMethods.ResumeThread(ThreadHandle) == 0xFFFFFFFFu)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "ResumeThread failed");
            }
            catch
            {
                try { NativeMethods.TerminateProcess(ProcessHandle, 1); } catch { }
                Dispose();
                throw;
            }
        }

        public bool TryWaitExit(int timeoutMs, out uint exitCode)
        {
            exitCode = 0;
            if (ProcessHandle == IntPtr.Zero) return true;
            uint rc = NativeMethods.WaitForSingleObject(ProcessHandle, (uint)timeoutMs);
            if (rc != NativeMethods.WAIT_OBJECT_0) return false;
            NativeMethods.GetExitCodeProcess(ProcessHandle, out exitCode);
            return true;
        }

        public void TryTerminate()
        {
            if (ProcessHandle != IntPtr.Zero)
            {
                try { NativeMethods.TerminateProcess(ProcessHandle, 1); } catch { }
            }
        }

        public void Dispose()
        {
            if (ThreadHandle  != IntPtr.Zero) { NativeMethods.CloseHandle(ThreadHandle);  ThreadHandle  = IntPtr.Zero; }
            if (ProcessHandle != IntPtr.Zero) { NativeMethods.CloseHandle(ProcessHandle); ProcessHandle = IntPtr.Zero; }
        }

        private static byte[] BuildEnvironmentBlock(string pipeName)
        {
            var env = Environment.GetEnvironmentVariables();
            env[ApimonProto.PIPE_ENV_NAME] = pipeName;

            var sb = new StringBuilder();
            foreach (DictionaryEntry kv in env)
            {
                sb.Append(kv.Key);
                sb.Append('=');
                sb.Append(kv.Value);
                sb.Append('\0');
            }
            sb.Append('\0');
            return Encoding.Unicode.GetBytes(sb.ToString());
        }
    }
}
