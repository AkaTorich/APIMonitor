using System;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using APIMonitor.Model;
using APIMonitor.Net;

namespace APIMonitor.Services
{
    /// <summary>
    /// Remote-mode event source. Connects to an ApimonRelay running on the
    /// target machine (typically a VM), sends the path of the app to launch,
    /// and streams back decoded <see cref="ApiEvent"/>s into the EventStore -
    /// the same store the local reader feeds, so the rest of the GUI is
    /// unchanged. String arguments aren't resolved remotely (the relay has the
    /// target memory, not the GUI), so args show with types + hex values.
    /// </summary>
    public sealed class RemoteClient : IDisposable
    {
        private readonly EventStore _store;
        private TcpClient _tcp;
        private CancellationTokenSource _cts;
        private Task _worker;

        /// <summary>Raised (on a background thread) when the connection ends -
        /// relay closed it, target exited, or an error occurred. Message is a
        /// short human-readable reason.</summary>
        public event Action<string> Disconnected;

        public RemoteClient(EventStore store)
        {
            _store = store;
        }

        public void Start(string host, int port, string targetPath)
        {
            _cts = new CancellationTokenSource();
            _worker = Task.Run(() => Loop(host, port, targetPath, _cts.Token));
        }

        private void Loop(string host, int port, string targetPath, CancellationToken ct)
        {
            string reason = "Disconnected.";
            try
            {
                _tcp = new TcpClient();
                _tcp.Connect(host, port);
                _tcp.NoDelay = true;

                NetworkStream ns = _tcp.GetStream();
                var bw = new BinaryWriter(ns);
                bw.Write(ApiEventWire.ProtocolVersion);
                bw.Write(ApiEventWire.CmdLaunch);
                ApiEventWire.WriteString(bw, targetPath);
                bw.Flush();

                var br = new BinaryReader(ns);
                while (!ct.IsCancellationRequested)
                {
                    ApiEvent e = ApiEventWire.Read(br);   // EndOfStreamException on close
                    _store.Enqueue(e);
                }
            }
            catch (EndOfStreamException)
            {
                reason = "Remote session ended (target exited).";
            }
            catch (Exception ex)
            {
                reason = "Remote error: " + ex.Message;
            }
            finally
            {
                Disconnected?.Invoke(reason);
            }
        }

        public void Dispose()
        {
            try { _cts?.Cancel(); } catch { }
            try { _tcp?.Close(); } catch { }
            try { _worker?.Wait(TimeSpan.FromSeconds(1)); } catch { }
            _cts?.Dispose();
        }
    }
}
