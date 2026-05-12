using System;
using System.Collections.Generic;
using System.Text;
using APIMonitor.Model;
using APIMonitor.Native;
using APIMonitor.Services;

namespace APIMonitor.ViewModel
{
    /// <summary>
    /// One row in the DataGrid. Constructed once when the event arrives;
    /// no INotifyPropertyChanged needed since rows are immutable.
    ///
    /// If a Win32MetadataResolver is supplied, "module!Func(0x..., ...)"
    /// strings from the Hook DLL get rewritten with proper parameter names
    /// and types from Microsoft.Windows.SDK.Win32Metadata.
    /// </summary>
    public sealed class ApiEventVm
    {
        public int    Index    { get; }
        public string Time     { get; }
        public uint   Source   { get; }
        public string SourceText { get; }
        public uint   Pid      { get; }
        public uint   Tid      { get; }
        public string Module   { get; }
        public string Function { get; }
        public string Args     { get; }
        public string Ret      { get; }
        public string CallerModule { get; }

        public ApiEventVm(int index, ApiEvent ev, double secondsSinceStart,
                          Win32MetadataResolver winmd, TargetMemoryReader mem)
        {
            Index  = index;
            Time   = secondsSinceStart.ToString("F4");
            Source = ev.Source;
            SourceText = SourceToText(ev.Source);
            Pid    = ev.Pid;
            Tid    = ev.Tid;

            if (ev.Args != null)
            {
                Module       = ev.Module ?? string.Empty;
                Function     = ev.Function ?? string.Empty;
                Ret          = string.Empty;
                Args         = FormatArgsTyped(Module, Function, ev.Args, winmd, mem);
                CallerModule = ev.CallerModule ?? string.Empty;
                return;
            }

            var (mod, func, args, ret) = SplitText(ev.Text ?? string.Empty);
            Module       = mod;
            Function     = func;
            Ret          = ret;
            Args         = EnrichArgs(mod, func, args, winmd);
            CallerModule = ev.CallerModule ?? string.Empty;
        }

        public ApiEventVm(int index, ApiEvent ev, double secondsSinceStart, Win32MetadataResolver winmd)
            : this(index, ev, secondsSinceStart, winmd, null) { }

        public ApiEventVm(int index, ApiEvent ev, double secondsSinceStart)
            : this(index, ev, secondsSinceStart, null, null) { }

        private static bool IsWideStringType(string t)
        {
            return t == "PWSTR" || t == "LPWSTR" || t == "LPCWSTR" || t == "PCWSTR";
        }
        private static bool IsAnsiStringType(string t)
        {
            return t == "PSTR" || t == "LPSTR" || t == "LPCSTR" || t == "PCSTR";
        }
        private static bool IsSignedIntType(string t)
        {
            return t == "INT" || t == "INT64" || t == "LONG" || t == "LONGLONG"
                || t == "SHORT" || t == "CHAR" || t == "SBYTE" || t == "INT_PTR";
        }
        private static bool IsUnsignedIntType(string t)
        {
            return t == "UINT" || t == "UINT64" || t == "ULONG" || t == "ULONGLONG"
                || t == "DWORD" || t == "WORD"  || t == "BYTE"
                || t == "USHORT" || t == "UINT_PTR" || t == "SIZE_T";
        }
        private static int TypeBits(string t)
        {
            if (t == "INT64" || t == "UINT64" || t == "LONGLONG" || t == "ULONGLONG"
                || t == "INT_PTR" || t == "UINT_PTR" || t == "SIZE_T") return 64;
            if (t == "SHORT" || t == "USHORT" || t == "WORD") return 16;
            if (t == "CHAR" || t == "SBYTE" || t == "BYTE") return 8;
            return 32; // INT/UINT/LONG/ULONG/DWORD default
        }
        private static long SignExtend(ulong v, int bits)
        {
            if (bits == 64) return (long)v;
            ulong mask = (1UL << bits) - 1UL;
            ulong masked = v & mask;
            ulong signBit = 1UL << (bits - 1);
            if ((masked & signBit) != 0) masked |= ~mask;
            return (long)masked;
        }
        private static ulong MaskForBits(int bits)
        {
            if (bits >= 64) return ulong.MaxValue;
            return (1UL << bits) - 1UL;
        }

        private static string EscapeForLog(string s, int max)
        {
            if (s == null) return null;
            if (s.Length > max) s = s.Substring(0, max) + "...";
            var sb = new StringBuilder(s.Length + 4);
            foreach (var ch in s) {
                if (ch == '\\')      sb.Append(@"\\");
                else if (ch == '"')  sb.Append("\\\"");
                else if (ch == '\r') sb.Append(@"\r");
                else if (ch == '\n') sb.Append(@"\n");
                else if (ch == '\t') sb.Append(@"\t");
                else if (ch < 0x20)  sb.Append('?');
                else                 sb.Append(ch);
            }
            return sb.ToString();
        }

        private static string FormatArgsTyped(string module, string func, ulong[] args,
                                              Win32MetadataResolver winmd, TargetMemoryReader mem)
        {
            Win32MetadataResolver.ApiSignature sig =
                (winmd != null) ? winmd.Lookup(module, func) : null;

            int n;
            if (sig != null) n = Math.Min(sig.Params.Length, args.Length);
            else             n = 4;
            if (n > args.Length) n = args.Length;

            var sb = new StringBuilder(n * 32);
            for (int i = 0; i < n; i++)
            {
                if (i > 0) sb.Append(", ");
                if (sig == null)
                {
                    sb.Append("0x").Append(args[i].ToString("X16"));
                    continue;
                }

                var p = sig.Params[i];
                sb.Append(p.TypeName).Append(' ').Append(p.Name).Append('=');

                /* BOOL / BOOLEAN -> TRUE / FALSE for readability. */
                if (p.TypeName == "BOOL" || p.TypeName == "BOOLEAN")
                {
                    sb.Append((args[i] & 0xFFFFFFFFu) != 0 ? "TRUE" : "FALSE");
                    continue;
                }

                /* Plain integer types -> decimal (signed types respect sign).
                 * Pointer / HANDLE / flag-like types still go through hex. */
                if (IsSignedIntType(p.TypeName))
                {
                    int bits = TypeBits(p.TypeName);
                    long sv = SignExtend(args[i], bits);
                    sb.Append(sv);
                    continue;
                }
                if (IsUnsignedIntType(p.TypeName))
                {
                    ulong uv = args[i] & MaskForBits(TypeBits(p.TypeName));
                    sb.Append(uv);
                    continue;
                }

                bool isWide = IsWideStringType(p.TypeName);
                bool isAnsi = IsAnsiStringType(p.TypeName);
                if ((isWide || isAnsi) && mem != null && args[i] != 0)
                {
                    string s = isWide ? mem.ReadWide(args[i])
                                      : mem.ReadAnsi(args[i]);
                    if (s != null)
                    {
                        sb.Append(isWide ? "L\"" : "\"")
                          .Append(EscapeForLog(s, 200))
                          .Append('"');
                        continue;
                    }
                }

                sb.Append("0x").Append(args[i].ToString("X16"));
            }
            return sb.ToString();
        }

        private static string SourceToText(uint s)
        {
            switch (s)
            {
                case 0: return "USER";
                case 1: return "COM";
                case 2: return "KERN";
                case 3: return "WEIRD";
                default: return "?";
            }
        }

        private static (string module, string func, string args, string ret) SplitText(string text)
        {
            // Expected shapes (Hook DLL trampoline engine):
            //   "kernel32.dll!CreateFileW(0x..., 0x..., 0x..., 0x...)"
            //   "kernel32.dll!CreateFileW(0x...) -> 0x..."   (legacy / x86 D86K)
            //   "PROCESS_CREATE pid=N parent=M cmd=\"...\""  (driver, no parens)
            //   "=== Hook engine attached ==="

            int parenOpen = text.IndexOf('(');
            int retSep    = text.IndexOf(" -> ");

            if (parenOpen <= 0)
                return (string.Empty, text, string.Empty, string.Empty);

            string head = text.Substring(0, parenOpen);
            string mod = string.Empty;
            string func = head;
            int bang = head.IndexOf('!');
            if (bang > 0)
            {
                mod  = head.Substring(0, bang);
                func = head.Substring(bang + 1);
            }

            int argsStart = parenOpen + 1;
            int argsEnd;
            string ret;
            if (retSep > parenOpen)
            {
                argsEnd = text.LastIndexOf(')', retSep);
                if (argsEnd < argsStart) argsEnd = retSep;
                ret = text.Substring(retSep + 4);
            }
            else
            {
                argsEnd = text.LastIndexOf(')');
                if (argsEnd < argsStart) argsEnd = text.Length;
                ret = string.Empty;
            }

            string args = text.Substring(argsStart, argsEnd - argsStart);
            return (mod, func, args, ret);
        }

        private static string EnrichArgs(string module, string func, string rawArgs, Win32MetadataResolver winmd)
        {
            if (winmd == null || string.IsNullOrEmpty(func) || string.IsNullOrEmpty(rawArgs))
                return rawArgs;

            var sig = winmd.Lookup(module, func);
            if (sig == null) return rawArgs;

            // Split rawArgs by ", " - Hook DLL emits exactly that separator.
            var parts = SplitArgs(rawArgs);
            var sb = new StringBuilder(rawArgs.Length + sig.Params.Length * 24);
            int n = Math.Min(parts.Count, sig.Params.Length);
            for (int i = 0; i < n; i++)
            {
                if (i > 0) sb.Append(", ");
                var p = sig.Params[i];
                sb.Append(p.TypeName).Append(' ').Append(p.Name).Append('=').Append(parts[i]);
            }
            // If the wrapper printed more dwords than the API takes (we always
            // log 4) - tag the remainder as garbage so the user doesn't read
            // them as real parameters.
            for (int i = n; i < parts.Count; i++)
            {
                sb.Append(", <unused>=").Append(parts[i]);
            }
            return sb.ToString();
        }

        private static List<string> SplitArgs(string raw)
        {
            // Hook DLL never quotes, never nests - simple comma+space split is safe.
            var list = new List<string>();
            int start = 0;
            for (int i = 0; i < raw.Length; i++)
            {
                if (i + 1 < raw.Length && raw[i] == ',' && raw[i + 1] == ' ')
                {
                    list.Add(raw.Substring(start, i - start));
                    i++;
                    start = i + 1;
                }
            }
            if (start <= raw.Length) list.Add(raw.Substring(start));
            return list;
        }
    }
}
