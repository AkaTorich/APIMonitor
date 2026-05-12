using System;
using System.Runtime.InteropServices;
using System.Text;

namespace APIMonitor.Services
{
    /// <summary>
    /// Holds an open handle to the monitored process and reads small strings
    /// out of its address space so the GUI can show "lpFileName=L\"...\""
    /// instead of bare pointer values.
    /// </summary>
    public sealed class TargetMemoryReader : IDisposable
    {
        private const uint PROCESS_VM_READ          = 0x0010;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInherit, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer, IntPtr nSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("psapi.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool EnumProcessModulesEx(IntPtr hProcess,
            [Out] IntPtr[] lphModule, uint cb, out uint lpcbNeeded, uint dwFilterFlag);

        [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetModuleBaseNameW(IntPtr hProcess, IntPtr hModule,
            System.Text.StringBuilder lpBaseName, uint nSize);

        [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetModuleFileNameExW(IntPtr hProcess, IntPtr hModule,
            System.Text.StringBuilder lpFilename, uint nSize);

        [StructLayout(LayoutKind.Sequential)]
        private struct MODULEINFO
        {
            public IntPtr lpBaseOfDll;
            public uint   SizeOfImage;
            public IntPtr EntryPoint;
        }

        [DllImport("psapi.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule,
            out MODULEINFO lpmodinfo, uint cb);

        private const uint LIST_MODULES_ALL = 0x03;

        private struct ModuleRange
        {
            public ulong  Base;
            public ulong  End;
            public string Name;
            public string FullPath;
        }
        private ModuleRange[] _modulesCache;
        private long _modulesCacheStamp;

        private IntPtr _hProc;

        public TargetMemoryReader(uint pid)
        {
            _hProc = OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
                false, pid);
        }

        /// <summary>
        /// Returns "name.dll" (lower-case) of the module that contains
        /// <paramref name="addr"/> in the target process, or null if not in
        /// any loaded module. Caches the module list and refreshes every
        /// 500 ms - cheap enough to call on every weird-syscall event.
        /// </summary>
        public string ResolveModule(ulong addr)
        {
            if (_hProc == IntPtr.Zero || addr == 0) return null;
            EnsureFreshCache();
            if (_modulesCache == null) return null;

            for (int i = 0; i < _modulesCache.Length; i++)
            {
                if (addr >= _modulesCache[i].Base && addr < _modulesCache[i].End)
                    return _modulesCache[i].Name;
            }
            return null;
        }

        public string ResolveModulePath(ulong addr)
        {
            if (_hProc == IntPtr.Zero || addr == 0) return null;
            EnsureFreshCache();
            if (_modulesCache == null) return null;

            for (int i = 0; i < _modulesCache.Length; i++)
            {
                if (addr >= _modulesCache[i].Base && addr < _modulesCache[i].End)
                    return _modulesCache[i].FullPath;
            }
            return null;
        }

        private void EnsureFreshCache()
        {
            long now = Environment.TickCount;
            if (_modulesCache == null || (now - _modulesCacheStamp) > 500)
            {
                RebuildModuleCache();
                _modulesCacheStamp = now;
            }
        }

        private void RebuildModuleCache()
        {
            // Two-pass EnumProcessModulesEx.
            uint needed;
            if (!EnumProcessModulesEx(_hProc, null, 0, out needed, LIST_MODULES_ALL))
                return;
            if (needed == 0) { _modulesCache = new ModuleRange[0]; return; }

            IntPtr[] handles = new IntPtr[needed / IntPtr.Size + 1];
            if (!EnumProcessModulesEx(_hProc, handles, (uint)(handles.Length * IntPtr.Size),
                                      out needed, LIST_MODULES_ALL))
                return;
            int count = (int)needed / IntPtr.Size;
            var list = new System.Collections.Generic.List<ModuleRange>(count);
            var sb   = new System.Text.StringBuilder(260);
            for (int i = 0; i < count; i++)
            {
                MODULEINFO mi;
                if (!GetModuleInformation(_hProc, handles[i], out mi, (uint)Marshal.SizeOf(typeof(MODULEINFO))))
                    continue;
                sb.Length = 0;
                if (GetModuleBaseNameW(_hProc, handles[i], sb, (uint)sb.Capacity) == 0)
                    continue;

                ulong baseAddr = (ulong)mi.lpBaseOfDll.ToInt64();
                string baseName = sb.ToString().ToLowerInvariant();

                var pathSb = new System.Text.StringBuilder(520);
                string fullPath = baseName;
                if (GetModuleFileNameExW(_hProc, handles[i], pathSb, (uint)pathSb.Capacity) > 0)
                    fullPath = pathSb.ToString();

                list.Add(new ModuleRange {
                    Base     = baseAddr,
                    End      = baseAddr + mi.SizeOfImage,
                    Name     = baseName,
                    FullPath = fullPath
                });
            }
            _modulesCache = list.ToArray();
        }

        public IntPtr GetProcessHandle() => _hProc;

        public bool IsValid => _hProc != IntPtr.Zero;

        public string ReadWide(ulong addr, int maxChars = 260)
        {
            if (_hProc == IntPtr.Zero || addr == 0) return null;
            byte[] buf = new byte[maxChars * 2];
            if (!ReadProcessMemory(_hProc, (IntPtr)(long)addr, buf, (IntPtr)buf.Length, out IntPtr read))
                return null;
            int total = read.ToInt32();
            int chars = 0;
            while ((chars + 1) * 2 <= total &&
                   !(buf[chars * 2] == 0 && buf[chars * 2 + 1] == 0))
                chars++;
            if (chars == 0) return string.Empty;
            return Encoding.Unicode.GetString(buf, 0, chars * 2);
        }

        public string ReadAnsi(ulong addr, int maxChars = 260)
        {
            if (_hProc == IntPtr.Zero || addr == 0) return null;
            byte[] buf = new byte[maxChars];
            if (!ReadProcessMemory(_hProc, (IntPtr)(long)addr, buf, (IntPtr)buf.Length, out IntPtr read))
                return null;
            int total = read.ToInt32();
            int chars = 0;
            while (chars < total && buf[chars] != 0) chars++;
            if (chars == 0) return string.Empty;
            return Encoding.ASCII.GetString(buf, 0, chars);
        }

        public void Dispose()
        {
            if (_hProc != IntPtr.Zero) {
                try { CloseHandle(_hProc); } catch { }
                _hProc = IntPtr.Zero;
            }
        }
    }
}
