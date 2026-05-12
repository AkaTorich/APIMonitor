using System;
using System.Runtime.InteropServices;

namespace APIMonitor.Native
{
    /// <summary>
    /// C# mirror of apimon_proto.h. Keep field order and sizes in sync.
    /// </summary>
    internal static class ApimonProto
    {
        public const uint SOURCE_USER_API = 0;
        public const uint SOURCE_USER_COM = 1;
        public const uint SOURCE_KERNEL   = 2;
        public const uint SOURCE_WEIRD    = 3;

        public const uint KSUB_PROC_CREATE = 0;
        public const uint KSUB_PROC_EXIT   = 1;
        public const uint KSUB_IMAGE_LOAD  = 2;

        public const int MAX_TEXT_WCHARS = 1024;

        public const string PIPE_ENV_NAME    = "APIMON_PIPE";
        public const string DEVICE_USER_PATH = @"\\.\APIMonitorDrv";
        public const string SERVICE_NAME     = "APIMonitorDrv";

        // CTL_CODE(0x8000, function, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0)
        // = (devType << 16) | (access << 14) | (function << 2) | method
        public static readonly uint IOCTL_SET_TARGET_PID = MakeIoctl(0x800);
        public static readonly uint IOCTL_CLEAR_TARGET   = MakeIoctl(0x801);
        public static readonly uint IOCTL_GET_EVENT      = MakeIoctl(0x802);
        public static readonly uint IOCTL_INJECT_DLL     = MakeIoctl(0x803);

        private static uint MakeIoctl(uint function)
        {
            const uint deviceType = 0x8000;
            const uint access = 0;     // FILE_ANY_ACCESS
            const uint method = 0;     // METHOD_BUFFERED
            return (deviceType << 16) | (access << 14) | (function << 2) | method;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct EventHeader
        {
            public uint TotalSize;
            public uint Pid;
            public uint Tid;
            public ulong TimestampQpc;
            public uint Source;
            public uint Subcategory;
            public uint TextOffset;
            public uint TextLength; // in WCHARs, no NUL
        }

        public static readonly int HeaderSize = Marshal.SizeOf(typeof(EventHeader));
    }
}
