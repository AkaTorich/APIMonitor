using System.IO;
using System.Text;
using APIMonitor.Model;

namespace APIMonitor.Net
{
    /// <summary>
    /// Binary serialization of a decoded <see cref="ApiEvent"/> for the remote
    /// relay transport. The relay (running on the target VM) reads the shared
    /// ring, resolves caller modules, and streams these records over TCP to the
    /// GUI, which feeds them into its EventStore exactly like the local reader.
    ///
    /// One record per event, written/read sequentially on the stream. No outer
    /// framing is needed because both sides agree on the field layout.
    /// </summary>
    public static class ApiEventWire
    {
        // Bumped if the layout changes; sent once right after connect.
        public const int ProtocolVersion = 2;

        // Command byte the GUI sends after the version. The relay loops on
        // these until the connection closes (LAUNCH is terminal - it then
        // streams events until the target exits).
        public const byte CmdListDir = 1;   // arg: path (UTF8, empty = drive roots) -> directory listing
        public const byte CmdLaunch  = 2;   // arg: path -> launch + inject + stream events

        public static void WriteString(BinaryWriter w, string s)
        {
            if (s == null) { w.Write(-1); return; }
            byte[] b = Encoding.UTF8.GetBytes(s);
            w.Write(b.Length);
            w.Write(b);
        }

        public static string ReadString(BinaryReader r)
        {
            int len = r.ReadInt32();
            if (len < 0) return null;
            byte[] b = r.ReadBytes(len);
            return Encoding.UTF8.GetString(b);
        }

        public static void Write(BinaryWriter w, ApiEvent e)
        {
            w.Write(e.Pid);
            w.Write(e.Tid);
            w.Write(e.TimestampQpc);
            w.Write(e.Source);
            w.Write(e.Subcategory);
            w.Write(e.Kind);
            w.Write(e.CallId);
            w.Write(e.RetValue);
            WriteString(w, e.Module);
            WriteString(w, e.Function);
            WriteString(w, e.CallerModule);
            WriteString(w, e.Text);

            if (e.Args == null)
            {
                w.Write((byte)0);
            }
            else
            {
                w.Write((byte)1);
                for (int i = 0; i < 12; i++)
                    w.Write(i < e.Args.Length ? e.Args[i] : 0UL);
            }
        }

        public static ApiEvent Read(BinaryReader r)
        {
            var e = new ApiEvent
            {
                Pid          = r.ReadUInt32(),
                Tid          = r.ReadUInt32(),
                TimestampQpc = r.ReadUInt64(),
                Source       = r.ReadUInt32(),
                Subcategory  = r.ReadUInt32(),
                Kind         = r.ReadUInt32(),
                CallId       = r.ReadUInt32(),
                RetValue     = r.ReadUInt64(),
            };
            e.Module       = ReadString(r);
            e.Function     = ReadString(r);
            e.CallerModule = ReadString(r);
            e.Text         = ReadString(r);

            byte hasArgs = r.ReadByte();
            if (hasArgs != 0)
            {
                var args = new ulong[12];
                for (int i = 0; i < 12; i++) args[i] = r.ReadUInt64();
                e.Args = args;
            }
            return e;
        }
    }
}
