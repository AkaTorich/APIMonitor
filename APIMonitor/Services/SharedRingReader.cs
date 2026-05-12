using System;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using APIMonitor.Model;
using APIMonitor.Native;

namespace APIMonitor.Services
{
    /// <summary>
    /// Opens "Local\apimon_ring_&lt;pid&gt;" (the file mapping the Hook DLL
    /// publishes events to) and polls it on a background task. Replaces the
    /// old named-pipe transport: zero kernel32 calls on the Hook DLL hot
    /// path, so we can hook every WinAPI without recursing through our own
    /// logger.
    /// </summary>
    public sealed class SharedRingReader : IDisposable
    {
        // Must match apimon_proto.h.
        private const int CAPACITY    = 32768;
        private const int MAX_SLOTS   = 32768;
        private const int MOD_LEN     = 40;
        private const int NAME_LEN    = 80;
        private const uint MAGIC      = 0x4D495041u; // 'APIM' little-endian

        // Header layout: 4*UINT32 + 3*LONG + UINT32 = 32 bytes
        private const int HEADER_FIXED_SIZE = 32;
        private const int SLOT_SIZE         = MOD_LEN + NAME_LEN;          // 120
        private const int SLOTS_BYTES       = MAX_SLOTS * SLOT_SIZE;       // 3,932,160
        private const int SLOTS_OFFSET      = HEADER_FIXED_SIZE;
        private const int EVENTS_OFFSET     = SLOTS_OFFSET + SLOTS_BYTES;

        // Event layout: ts_qpc(8) + pid(4) + tid(4) + slot_id(4) + source(4) + caller_addr(8) + 12*UINT64
        private const int EVENT_SIZE        = 8 + 4 + 4 + 4 + 4 + 8 + 12 * 8;  // 128

        private readonly EventStore _store;
        private readonly uint _pid;
        private readonly TargetMemoryReader _mem;
        private MemoryMappedFile _mmf;
        private MemoryMappedViewAccessor _view;
        private CancellationTokenSource _cts;
        private Task _worker;

        public SharedRingReader(EventStore store, uint pid, TargetMemoryReader mem)
        {
            _store = store;
            _pid = pid;
            _mem = mem;
        }

        public bool TryOpen()
        {
            string name = "Local\\apimon_ring_" + _pid;
            try
            {
                // The Hook DLL creates the mapping inside the target. We
                // open it; if the target hasn't created it yet we'll retry
                // a few times in the worker.
                _mmf  = MemoryMappedFile.OpenExisting(name, MemoryMappedFileRights.ReadWrite);
                _view = _mmf.CreateViewAccessor();
                return true;
            }
            catch
            {
                // Not ready - the worker will retry.
                return false;
            }
        }

        public void Start()
        {
            _cts = new CancellationTokenSource();
            _worker = Task.Run(() => Loop(_cts.Token));
        }

        private async Task Loop(CancellationToken ct)
        {
            // Wait until the target has created the mapping.
            string name = "Local\\apimon_ring_" + _pid;
            while (!ct.IsCancellationRequested && _mmf == null)
            {
                try
                {
                    _mmf  = MemoryMappedFile.OpenExisting(name, MemoryMappedFileRights.ReadWrite);
                    _view = _mmf.CreateViewAccessor();
                    break;
                }
                catch
                {
                    try { await Task.Delay(50, ct).ConfigureAwait(false); } catch { return; }
                }
            }
            if (ct.IsCancellationRequested) return;

            int  read_seq = 0;
            uint magic    = _view.ReadUInt32(0);
            if (magic != MAGIC)
            {
                // Wait until the Hook DLL has populated the header.
                while (!ct.IsCancellationRequested && magic != MAGIC)
                {
                    try { await Task.Delay(20, ct).ConfigureAwait(false); } catch { return; }
                    magic = _view.ReadUInt32(0);
                }
            }

            // Snapshot capacity / max_slots from header.
            int capacity  = _view.ReadInt32(8);
            int maxSlots  = _view.ReadInt32(12);
            if (capacity <= 0 || (capacity & (capacity - 1)) != 0) capacity = CAPACITY;

            byte[] modBuf  = new byte[MOD_LEN];
            byte[] nameBuf = new byte[NAME_LEN];

            while (!ct.IsCancellationRequested)
            {
                int writeSeq = _view.ReadInt32(16);    // offsetof(write_seq)
                while (read_seq < writeSeq)
                {
                    int idx = read_seq & (capacity - 1);
                    long evOff = EVENTS_OFFSET + (long)idx * EVENT_SIZE;

                    ulong tsQpc  = _view.ReadUInt64(evOff + 0);
                    uint  pid    = _view.ReadUInt32(evOff + 8);
                    uint  tid    = _view.ReadUInt32(evOff + 12);
                    uint  slotId = _view.ReadUInt32(evOff + 16);
                    uint  source = _view.ReadUInt32(evOff + 20);
                    ulong callerAddr = _view.ReadUInt64(evOff + 24);
                    ulong[] args = new ulong[12];
                    for (int k = 0; k < 12; k++)
                        args[k] = _view.ReadUInt64(evOff + 32 + k * 8);

                    string callerPath = (_mem != null) ? _mem.ResolveModulePath(callerAddr) : null;

                    /* Drop everything that doesn't have a resolvable caller
                     * module (those are typically internal kernel32/CRT
                     * calls whose return address landed in pages we
                     * couldn't resolve), and everything that DID resolve
                     * to a noise module. Net result: only calls coming
                     * from the target's own modules survive. */
                    if (string.IsNullOrEmpty(callerPath) || IsNoiseCaller(callerPath))
                    {
                        read_seq++;
                        continue;
                    }

                    string mod = "?", fn = "?";
                    if (slotId < maxSlots)
                    {
                        long slotOff = SLOTS_OFFSET + (long)slotId * SLOT_SIZE;
                        _view.ReadArray(slotOff, modBuf, 0, MOD_LEN);
                        _view.ReadArray(slotOff + MOD_LEN, nameBuf, 0, NAME_LEN);
                        mod = ZString(modBuf);
                        fn  = ZString(nameBuf);
                    }

                    /* Hand the raw arg array to the ViewModel - it trims
                     * to the real arity via Win32Metadata. */
                    _store.Enqueue(new ApiEvent {
                        Pid          = pid,
                        Tid          = tid,
                        TimestampQpc = tsQpc,
                        Source       = source,
                        Subcategory  = 0,
                        Module       = mod,
                        Function     = fn,
                        Args         = args,
                        CallerModule = callerPath,
                        Text         = null,
                    });

                    read_seq++;
                }

                try { await Task.Delay(10, ct).ConfigureAwait(false); } catch { return; }
            }
        }

        /// <summary>
        /// True if the caller is internal noise: our own Hook DLL, the C
        /// runtime, or any module living under System32/SysWOW64/WinSxS
        /// (those are system-internal calls, e.g. CoreMessaging.dll calling
        /// kernel32!TlsGetValue - the user wants to see what *their* code
        /// is doing, not how Windows internally bookkeeps itself).
        /// </summary>
        private static bool IsNoiseCaller(string path)
        {
            string lower = path.ToLowerInvariant();

            // Hook DLL.
            if (lower.EndsWith("\\apihook64.dll") || lower.EndsWith("\\apihook32.dll"))
                return true;

            // Any system folder = system-to-system call.
            if (lower.IndexOf("\\system32\\")  >= 0) return true;
            if (lower.IndexOf("\\syswow64\\")  >= 0) return true;
            if (lower.IndexOf("\\winsxs\\")    >= 0) return true;

            // Just in case CRT lives somewhere else (private deployment).
            int slash = lower.LastIndexOfAny(new[] { '\\', '/' });
            string file = (slash >= 0) ? lower.Substring(slash + 1) : lower;
            if (file.StartsWith("ucrtbase"))   return true;
            if (file.StartsWith("msvcrt"))     return true;
            if (file.StartsWith("vcruntime"))  return true;
            if (file.StartsWith("msvcp"))      return true;
            return false;
        }

        private static string ZString(byte[] b)
        {
            int n = 0;
            while (n < b.Length && b[n] != 0) n++;
            return System.Text.Encoding.ASCII.GetString(b, 0, n);
        }

        public void Dispose()
        {
            try { _cts?.Cancel(); } catch { }
            try { _worker?.Wait(TimeSpan.FromSeconds(1)); } catch { }
            try { _view?.Dispose(); } catch { }
            try { _mmf?.Dispose(); } catch { }
            _cts?.Dispose();
        }
    }
}
