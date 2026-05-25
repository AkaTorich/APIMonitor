using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using APIMonitor.Model;
using APIMonitor.Net;
using APIMonitor.Services;

namespace ApimonRelay
{
    /// <summary>
    /// Remote relay agent. Run this elevated on the target machine (e.g. a VM)
    /// next to APIHook64.dll, APIHook32.dll and Injector32.exe. The APIMonitor
    /// GUI connects over TCP, sends the path of an app to launch, and the relay
    /// launches + injects it locally, reads its shared-event ring, resolves
    /// caller modules, and streams decoded events back to the GUI.
    ///
    ///   ApimonRelay.exe [port]      (default port 28080)
    /// </summary>
    internal static class Program
    {
        private static int Main(string[] args)
        {
            int port = 28080;
            if (args.Length >= 1 && int.TryParse(args[0], out int p) && p > 0 && p <= 65535)
                port = p;

            string baseDir = AppDomain.CurrentDomain.BaseDirectory;

            TcpListener listener;
            try
            {
                listener = new TcpListener(IPAddress.Any, port);
                listener.Start();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Failed to listen on port " + port + ": " + ex.Message);
                return 1;
            }

            Console.WriteLine("ApimonRelay listening on 0.0.0.0:" + port);
            Console.WriteLine("Hook DLLs / Injector32.exe expected in: " + baseDir);
            Console.WriteLine("Waiting for APIMonitor GUI to connect (Ctrl+C to quit)...");

            while (true)
            {
                TcpClient client;
                try { client = listener.AcceptTcpClient(); }
                catch (Exception ex) { Console.Error.WriteLine("Accept failed: " + ex.Message); break; }

                Console.WriteLine("--- Client connected from " + client.Client.RemoteEndPoint + " ---");
                try { HandleSession(client, baseDir); }
                catch (Exception ex) { Console.Error.WriteLine("Session error: " + ex.Message); }
                finally { try { client.Close(); } catch { } }
                Console.WriteLine("--- Session ended ---");
            }
            return 0;
        }

        private static void HandleSession(TcpClient client, string baseDir)
        {
            client.NoDelay = true;
            using (NetworkStream ns = client.GetStream())
            {
                var br = new BinaryReader(ns);
                var bw = new BinaryWriter(ns);

                int ver = br.ReadInt32();
                if (ver != ApiEventWire.ProtocolVersion)
                    Console.WriteLine("WARNING: protocol mismatch (relay=" +
                                      ApiEventWire.ProtocolVersion + ", gui=" + ver + ")");

                // Command loop: directory listings until the GUI issues LAUNCH.
                while (true)
                {
                    byte cmd;
                    try { cmd = br.ReadByte(); }
                    catch (EndOfStreamException) { return; }   // GUI closed (e.g. browse done)

                    if (cmd == ApiEventWire.CmdListDir)
                    {
                        string dir = ApiEventWire.ReadString(br);
                        WriteListing(bw, dir);
                        continue;
                    }
                    if (cmd == ApiEventWire.CmdLaunch)
                    {
                        string targetPath = ApiEventWire.ReadString(br);
                        Console.WriteLine("Launch request: " + targetPath);
                        StreamTarget(client, ns, bw, baseDir, targetPath);
                        return;   // launch is terminal for the connection
                    }
                    Console.WriteLine("Unknown command byte: " + cmd);
                    return;
                }
            }
        }

        private static void WriteListing(BinaryWriter bw, string dir)
        {
            try
            {
                if (string.IsNullOrEmpty(dir))
                {
                    var drives = System.IO.DriveInfo.GetDrives();
                    bw.Write((byte)1);
                    var ready = System.Array.FindAll(drives, d => d.IsReady);
                    bw.Write(ready.Length);
                    foreach (var d in ready)
                    {
                        bw.Write((byte)1);                  // isDir
                        ApiEventWire.WriteString(bw, d.Name); // "C:\"
                    }
                    bw.Flush();
                    return;
                }

                string[] dirs  = Directory.GetDirectories(dir);
                string[] files = Directory.GetFiles(dir, "*.exe");
                bw.Write((byte)1);
                bw.Write(dirs.Length + files.Length);
                foreach (var d in dirs)
                {
                    bw.Write((byte)1);
                    ApiEventWire.WriteString(bw, new DirectoryInfo(d).Name);
                }
                foreach (var f in files)
                {
                    bw.Write((byte)0);
                    ApiEventWire.WriteString(bw, Path.GetFileName(f));
                }
                bw.Flush();
            }
            catch (Exception ex)
            {
                bw.Write((byte)0);                       // not ok
                ApiEventWire.WriteString(bw, ex.Message);
                bw.Flush();
            }
        }

        private static void StreamTarget(TcpClient client, NetworkStream ns, BinaryWriter bw,
                                         string baseDir, string targetPath)
        {
                var store     = new EventStore();
                var launcher  = new Launcher(baseDir, null, null);   // no kernel driver in relay v1
                TargetMemoryReader mem = null;
                SharedRingReader   reader = null;

                try
                {
                    launcher.Launch(targetPath);
                    Console.WriteLine("Launched pid=" + launcher.Pid +
                                      " (" + (launcher.TargetIs64Bit ? "x64" : "x86") + ")");

                    mem    = new TargetMemoryReader(launcher.Pid);
                    reader = new SharedRingReader(store, launcher.Pid, mem);
                    reader.Start();

                    long sent = 0;

                    while (true)
                    {
                        // GUI disconnected? (socket readable with 0 bytes available)
                        if (client.Client.Poll(0, SelectMode.SelectRead) && client.Available == 0)
                        {
                            Console.WriteLine("GUI disconnected.");
                            break;
                        }

                        bool wrote = false;
                        while (store.TryDequeue(out ApiEvent e))
                        {
                            ApiEventWire.Write(bw, e);
                            wrote = true;
                            sent++;
                        }
                        if (wrote) bw.Flush();

                        if (launcher.TryWaitExit(0, out uint code))
                        {
                            // flush any tail events, then end the session
                            while (store.TryDequeue(out ApiEvent e2)) ApiEventWire.Write(bw, e2);
                            bw.Flush();
                            Console.WriteLine("Target exited (code=" + code + "). Events sent: " + sent);
                            break;
                        }

                        Thread.Sleep(5);
                    }
                }
                finally
                {
                    try { reader?.Dispose(); } catch { }
                    try { mem?.Dispose(); } catch { }
                    try { launcher.TryTerminate(); } catch { }
                    try { launcher.Dispose(); } catch { }
                }
        }
    }
}
