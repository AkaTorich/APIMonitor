namespace APIMonitor.Model
{
    /// <summary>
    /// Decoded event from Hook DLL via the shared-memory ring.
    /// Module/Function are populated when the slot table maps slot_id;
    /// Args is a fixed 12-element array of raw ULONG_PTR values (zero-padded
    /// for functions with fewer arguments). The ViewModel layer trims to the
    /// real arity using Win32Metadata.
    /// </summary>
    public sealed class ApiEvent
    {
        public uint   Pid;
        public uint   Tid;
        public ulong  TimestampQpc;
        public uint   Source;
        public uint   Subcategory;
        public string Module;
        public string Function;
        public ulong[] Args;             // length = 12
        public string CallerModule;      // full path of the module the call came from
        public string Text;              // legacy "Function(args) -> ret" line; null when Module/Function/Args are set
    }
}
