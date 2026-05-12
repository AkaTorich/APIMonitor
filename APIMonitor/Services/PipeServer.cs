using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using APIMonitor.Model;
using APIMonitor.Native;

namespace APIMonitor.Services
{
    /// <summary>
    /// Pool of NamedPipeServerStream instances. The injected Hook DLL connects
    /// to APIMON_PIPE and writes APIMON_EVENT_HEADER + UTF-16 text per message.
    /// </summary>
    public sealed class PipeServer : IDisposable
    {
        private const int PoolSize = 4;
        private const int ReadBufferSize = 64 * 1024;

        private readonly EventStore _store;
        private readonly string _pipeName;
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();
        private Task[] _workers;

        public string PipeName => _pipeName;

        public PipeServer(EventStore store)
        {
            _store = store;
            byte[] rnd = new byte[6];
            using (var rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
                rng.GetBytes(rnd);
            _pipeName = "apimon_" + BitConverter.ToString(rnd).Replace("-", "").ToLowerInvariant();
        }

        public void Start()
        {
            _workers = new Task[PoolSize];
            for (int i = 0; i < PoolSize; i++)
                _workers[i] = Task.Run(() => WorkerLoopAsync(_cts.Token));
        }

        private async Task WorkerLoopAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                NamedPipeServerStream pipe = null;
                try
                {
                    var sec = new PipeSecurity();
                    sec.AddAccessRule(new PipeAccessRule(
                        new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                        PipeAccessRights.Write | PipeAccessRights.CreateNewInstance,
                        AccessControlType.Allow));
                    sec.AddAccessRule(new PipeAccessRule(
                        new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                        PipeAccessRights.FullControl,
                        AccessControlType.Allow));
                    sec.AddAccessRule(new PipeAccessRule(
                        WindowsIdentity.GetCurrent().Owner,
                        PipeAccessRights.FullControl,
                        AccessControlType.Allow));

                    pipe = new NamedPipeServerStream(
                        _pipeName,
                        PipeDirection.In,
                        NamedPipeServerStream.MaxAllowedServerInstances,
                        PipeTransmissionMode.Message,
                        PipeOptions.Asynchronous,
                        ReadBufferSize,
                        ReadBufferSize,
                        sec);

                    await Task.Factory.FromAsync(
                        pipe.BeginWaitForConnection,
                        pipe.EndWaitForConnection,
                        null).ConfigureAwait(false);

                    if (ct.IsCancellationRequested) break;

                    await ReadClientAsync(pipe, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) { }
                catch (Exception ex)
                {
                    Debug.WriteLine("PipeServer worker error: " + ex);
                }
                finally
                {
                    pipe?.Dispose();
                }
            }
        }

        private async Task ReadClientAsync(NamedPipeServerStream pipe, CancellationToken ct)
        {
            byte[] buf = new byte[ReadBufferSize];
            while (pipe.IsConnected && !ct.IsCancellationRequested)
            {
                int total = 0;
                int read;
                do
                {
                    try
                    {
                        read = await pipe.ReadAsync(buf, total, buf.Length - total, ct)
                                         .ConfigureAwait(false);
                    }
                    catch (IOException) { return; }
                    catch (ObjectDisposedException) { return; }

                    if (read == 0) return;
                    total += read;
                } while (!pipe.IsMessageComplete && total < buf.Length);

                if (total >= ApimonProto.HeaderSize)
                    DecodeAndEnqueue(buf, total);
            }
        }

        private void DecodeAndEnqueue(byte[] buf, int totalSize)
        {
            int o = 0;
            uint  size       = BitConverter.ToUInt32(buf, o);   o += 4;
            uint  pid        = BitConverter.ToUInt32(buf, o);   o += 4;
            uint  tid        = BitConverter.ToUInt32(buf, o);   o += 4;
            ulong qpc        = BitConverter.ToUInt64(buf, o);   o += 8;
            uint  source     = BitConverter.ToUInt32(buf, o);   o += 4;
            uint  subcat     = BitConverter.ToUInt32(buf, o);   o += 4;
            uint  textOff    = BitConverter.ToUInt32(buf, o);   o += 4;
            uint  textLenW   = BitConverter.ToUInt32(buf, o);   o += 4;

            if (textOff + textLenW * 2 > totalSize) return;
            if (textLenW > ApimonProto.MAX_TEXT_WCHARS) return;

            string text = System.Text.Encoding.Unicode.GetString(buf, (int)textOff, (int)textLenW * 2);

            _store.Enqueue(new ApiEvent
            {
                Pid          = pid,
                Tid          = tid,
                TimestampQpc = qpc,
                Source       = source,
                Subcategory  = subcat,
                Text         = text
            });
        }

        public void Dispose()
        {
            _cts.Cancel();
            try { Task.WaitAll(_workers ?? Array.Empty<Task>(), TimeSpan.FromSeconds(2)); } catch { }
            _cts.Dispose();
        }
    }
}
