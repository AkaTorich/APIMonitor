using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using APIMonitor.Native;

namespace APIMonitor.Services
{
    /// <summary>
    /// Install / start / stop the kernel driver service. Uses raw advapi32 for CreateService -
    /// System.ServiceProcess.ServiceController can only operate on existing services.
    /// </summary>
    public static class ServiceManager
    {
        public const int ERROR_SERVICE_EXISTS = 1073;
        public const int ERROR_INVALID_IMAGE_HASH = 577;
        public const int ERROR_FILE_NOT_FOUND = 2;

        public static void EnsureInstalledAndStarted(string sysFullPath)
        {
            IntPtr scm = NativeMethods.OpenSCManagerW(null, null, NativeMethods.SC_MANAGER_ALL_ACCESS);
            if (scm == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenSCManager failed");

            IntPtr svc = IntPtr.Zero;
            try
            {
                svc = NativeMethods.OpenServiceW(scm, ApimonProto.SERVICE_NAME,
                    NativeMethods.SERVICE_ALL_ACCESS);

                if (svc == IntPtr.Zero)
                {
                    svc = NativeMethods.CreateServiceW(
                        scm,
                        ApimonProto.SERVICE_NAME,
                        ApimonProto.SERVICE_NAME,
                        NativeMethods.SERVICE_ALL_ACCESS,
                        NativeMethods.SERVICE_KERNEL_DRIVER,
                        NativeMethods.SERVICE_DEMAND_START,
                        NativeMethods.SERVICE_ERROR_NORMAL,
                        sysFullPath,
                        null, IntPtr.Zero, null, null, null);

                    if (svc == IntPtr.Zero)
                    {
                        int err = Marshal.GetLastWin32Error();
                        throw new Win32Exception(err, "CreateService failed (err=" + err + ")");
                    }
                }

                if (!NativeMethods.StartServiceW(svc, 0, IntPtr.Zero))
                {
                    int err = Marshal.GetLastWin32Error();
                    // 1056 = ERROR_SERVICE_ALREADY_RUNNING - acceptable
                    if (err != 1056)
                    {
                        if (err == ERROR_INVALID_IMAGE_HASH)
                            throw new Win32Exception(err,
                                "Driver signature rejected. Run 'bcdedit /set testsigning on' as admin and reboot, " +
                                "then re-sign the .sys with a self-signed cert (see README).");
                        throw new Win32Exception(err, "StartService failed (err=" + err + ")");
                    }
                }
            }
            finally
            {
                if (svc != IntPtr.Zero) NativeMethods.CloseServiceHandle(svc);
                NativeMethods.CloseServiceHandle(scm);
            }
        }

        public static void TryStop()
        {
            try
            {
                using (var sc = new ServiceController(ApimonProto.SERVICE_NAME))
                {
                    if (sc.Status == ServiceControllerStatus.Running ||
                        sc.Status == ServiceControllerStatus.StartPending)
                    {
                        sc.Stop();
                        sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(5));
                    }
                }
            }
            catch
            {
                // Service might not exist; that's fine.
            }
        }

        public static bool IsRunning()
        {
            try
            {
                using (var sc = new ServiceController(ApimonProto.SERVICE_NAME))
                    return sc.Status == ServiceControllerStatus.Running;
            }
            catch { return false; }
        }
    }
}
