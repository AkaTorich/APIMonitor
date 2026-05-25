using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using APIMonitor.Net;

namespace APIMonitor.Services
{
    public sealed class RemoteEntry
    {
        public bool   IsDir;
        public string Name;
        // Shown in the picker list: folders flagged, executables plain.
        public string Display => IsDir ? "[DIR]  " + Name : "       " + Name;
    }

    /// <summary>
    /// Short-lived synchronous client used by the remote file-picker dialog.
    /// Holds one connection to the relay and issues directory-listing commands;
    /// the relay enumerates the VM's filesystem and replies. Closed when the
    /// dialog closes (a fresh connection is used for the actual launch).
    /// </summary>
    public sealed class RemoteBrowserClient : IDisposable
    {
        private TcpClient _tcp;
        private BinaryReader _br;
        private BinaryWriter _bw;

        public void Connect(string host, int port)
        {
            _tcp = new TcpClient();
            _tcp.Connect(host, port);
            _tcp.NoDelay = true;
            NetworkStream ns = _tcp.GetStream();
            _br = new BinaryReader(ns);
            _bw = new BinaryWriter(ns);
            _bw.Write(ApiEventWire.ProtocolVersion);
            _bw.Flush();
        }

        /// <summary>
        /// Lists <paramref name="path"/> on the remote machine. An empty path
        /// returns the drive roots. On a remote error, returns an empty list
        /// and sets <paramref name="error"/>.
        /// </summary>
        public List<RemoteEntry> List(string path, out string error)
        {
            error = null;
            _bw.Write(ApiEventWire.CmdListDir);
            ApiEventWire.WriteString(_bw, path ?? string.Empty);
            _bw.Flush();

            byte ok = _br.ReadByte();
            if (ok == 0)
            {
                error = ApiEventWire.ReadString(_br);
                return new List<RemoteEntry>();
            }

            int n = _br.ReadInt32();
            var list = new List<RemoteEntry>(n);
            for (int i = 0; i < n; i++)
            {
                bool isDir = _br.ReadByte() != 0;
                string name = ApiEventWire.ReadString(_br);
                list.Add(new RemoteEntry { IsDir = isDir, Name = name });
            }
            return list;
        }

        public void Dispose()
        {
            try { _tcp?.Close(); } catch { }
        }
    }
}
