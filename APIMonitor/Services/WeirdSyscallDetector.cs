using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using APIMonitor.Model;
using APIMonitor.Native;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;

namespace APIMonitor.Services
{
    /// <summary>
    /// Port of thefLink/Hunt-Weird-Syscalls (KrabsETW -> TraceEvent).
    ///
    /// Subscribes to "Microsoft-Windows-Kernel-Audit-API-Calls" with stack
    /// trace capture enabled. For every NtOpenThread (id 6) and
    /// NtSetContextThread (id 4) event in our target PID, walks the user-
    /// mode return-address stack:
    ///   * "Direct syscall"  - top-of-stack module is NOT ntdll/win32u/
    ///                         wow64win, i.e. the program executed the
    ///                         syscall instruction itself.
    ///   * "Indirect syscall"- top-of-stack is in ntdll but NOT inside
    ///                         the expected syscall stub (offset window
    ///                         &lt;= 23 bytes from the export entry).
    /// Both look bad: malware uses them to bypass user-mode API hooks.
    /// </summary>
    public sealed class WeirdSyscallDetector : IDisposable
    {
        private const int EVENTID_SETCONTEXTTHREAD = 4;
        private const int EVENTID_OPENTHREAD       = 6;

        private static readonly string[] AllowedModules = {
            "ntdll.dll", "win32u.dll", "wow64win.dll"
        };

        private readonly EventStore _store;
        private readonly uint _pid;
        private readonly TargetMemoryReader _mem;

        private TraceEventSession _session;
        private Task _worker;

        public WeirdSyscallDetector(EventStore store, uint pid, TargetMemoryReader mem)
        {
            _store = store;
            _pid   = pid;
            _mem   = mem;
        }

        public void Start()
        {
            // Unique name per pid so multiple runs don't clash.
            string sessionName = "APIMonitor_Weird_" + _pid;

            try
            {
                _session = new TraceEventSession(sessionName);
            }
            catch (UnauthorizedAccessException)
            {
                return; // need admin; the loader already required it but be safe
            }

            // Enable the provider with stack trace capture.
            var opt = new TraceEventProviderOptions {
                StacksEnabled = true
            };
            _session.EnableProvider("Microsoft-Windows-Kernel-Audit-API-Calls",
                                    TraceEventLevel.Always,
                                    ulong.MaxValue, opt);

            _session.Source.Dynamic.All += OnEvent;

            _worker = Task.Run(() => {
                try { _session.Source.Process(); } catch { /* session stopped */ }
            });
        }

        private void OnEvent(TraceEvent ev)
        {
            if (ev.ProcessID != (int)_pid) return;

            int id = (int)ev.ID;
            if (id != EVENTID_OPENTHREAD && id != EVENTID_SETCONTEXTTHREAD) return;

            // TODO: stack trace based direct/indirect detection.
            // Live TraceEventSession doesn't expose CallStack() directly;
            // doing it properly needs TraceLog (ETLX) or a parallel
            // Kernel StackWalkStack subscription. For now we just surface
            // the syscall - it's noisy but already a strong signal that
            // the target is doing thread injection.
            Push("CALL", id, ev);
        }

        private void Push(string kind, int eventId, TraceEvent ev)
        {
            string syscall = (eventId == EVENTID_OPENTHREAD) ? "NtOpenThread" : "NtSetContextThread";
            string text = kind + " " + syscall + "  tid=" + ev.ThreadID;

            _store.Enqueue(new ApiEvent {
                Pid          = (uint)ev.ProcessID,
                Tid          = (uint)ev.ThreadID,
                TimestampQpc = (ulong)ev.TimeStamp.Ticks,
                Source       = ApimonProto.SOURCE_WEIRD,
                Subcategory  = 0,
                Module       = "",
                Function     = syscall,
                Args         = null,
                Text         = text,
            });
        }

        public void Dispose()
        {
            try { _session?.Stop(); } catch { }
            try { _worker?.Wait(TimeSpan.FromSeconds(1)); } catch { }
            try { _session?.Dispose(); } catch { }
        }
    }
}
