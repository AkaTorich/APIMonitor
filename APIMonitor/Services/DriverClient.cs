using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using APIMonitor.Native;
using Microsoft.Win32.SafeHandles;

namespace APIMonitor.Services
{
    /// <summary>
    /// Opens \\.\APIMonitorDrv. Used by Injector for the kernel APC fallback
    /// (IOCTL_APIMON_INJECT_DLL) when user-mode CreateRemoteThread is blocked.
    /// Driver-side event polling (IOCTL_GET_EVENT) is intentionally not wired up:
    /// every IMAGE_LOAD flooded the DataGrid and the GUI only shows hook events.
    /// </summary>
    public sealed class DriverClient : IDisposable
    {
        private SafeFileHandle _hCtrl;

        public bool IsOpen => _hCtrl != null && !_hCtrl.IsInvalid && !_hCtrl.IsClosed;

        private static SafeFileHandle OpenDeviceHandle()
        {
            var h = NativeMethods.CreateFileW(
                ApimonProto.DEVICE_USER_PATH,
                NativeMethods.GENERIC_READ | NativeMethods.GENERIC_WRITE,
                0, IntPtr.Zero,
                NativeMethods.OPEN_EXISTING,
                NativeMethods.FILE_ATTRIBUTE_NORMAL,
                IntPtr.Zero);
            if (h.IsInvalid)
            {
                int err = Marshal.GetLastWin32Error();
                throw new Win32Exception(err, "CreateFile(\\\\.\\APIMonitorDrv) failed - is the driver running?");
            }
            return h;
        }

        public void Open()
        {
            _hCtrl = OpenDeviceHandle();
        }

        public void SetTargetPid(uint pid)
        {
            byte[] inBuf = BitConverter.GetBytes(pid);
            uint returned;
            if (!NativeMethods.DeviceIoControl(_hCtrl, ApimonProto.IOCTL_SET_TARGET_PID,
                    inBuf, (uint)inBuf.Length, null, 0, out returned, IntPtr.Zero))
            {
                int err = Marshal.GetLastWin32Error();
                throw new Win32Exception(err, "IOCTL_SET_TARGET_PID failed");
            }
        }

        public void ClearTarget()
        {
            uint returned;
            try
            {
                NativeMethods.DeviceIoControl(_hCtrl, ApimonProto.IOCTL_CLEAR_TARGET,
                    null, 0, null, 0, out returned, IntPtr.Zero);
            }
            catch { /* shutting down - swallow */ }
        }

        /// <summary>
        /// Asks the driver to inject the DLL into a process via kernel-mode APC.
        /// Used as fallback when user-mode CreateRemoteThread is blocked
        /// (PPL processes, mitigation policies, anti-malware services).
        /// </summary>
        public void InjectDll(uint pid, uint tid, ulong loadLibraryWAddr, string dllPath)
        {
            const int MaxPathW = 520;          // must match APIMON_MAX_DLL_PATH
            const int ReqSize  = 4 + 4 + 8 + MaxPathW * 2;

            if (string.IsNullOrEmpty(dllPath))
                throw new ArgumentException("dllPath empty");
            if (dllPath.Length >= MaxPathW)
                throw new ArgumentException("dllPath too long for kernel buffer");

            byte[] req = new byte[ReqSize];
            int o = 0;
            BitConverter.GetBytes(pid).CopyTo(req, o);                 o += 4;
            BitConverter.GetBytes(tid).CopyTo(req, o);                 o += 4;
            BitConverter.GetBytes(loadLibraryWAddr).CopyTo(req, o);    o += 8;

            byte[] pathBytes = System.Text.Encoding.Unicode.GetBytes(dllPath);
            Buffer.BlockCopy(pathBytes, 0, req, o, pathBytes.Length);

            uint returned;
            if (!NativeMethods.DeviceIoControl(_hCtrl, ApimonProto.IOCTL_INJECT_DLL,
                    req, (uint)req.Length, null, 0, out returned, IntPtr.Zero))
            {
                int err = Marshal.GetLastWin32Error();
                throw new Win32Exception(err, "IOCTL_APIMON_INJECT_DLL failed");
            }
        }

        public void Dispose()
        {
            try { _hCtrl?.Dispose(); } catch { }
        }
    }
}
