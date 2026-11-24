using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using APIMonitor.Model;
using APIMonitor.Native;
using APIMonitor.Services;
using Microsoft.Win32;

namespace APIMonitor.ViewModel
{
    public sealed class MainViewModel : INotifyPropertyChanged
    {
        // ---- bindable surface ----
        public BatchObservableCollection<ApiEventVm> VisibleEvents { get; } = new BatchObservableCollection<ApiEventVm>();
        public ObservableCollection<string> FilterOptions { get; } =
            new ObservableCollection<string> { "All", "User-mode (API)", "User-mode (COM)" };

        private string _targetPath = string.Empty;
        public  string TargetPath
        {
            get => _targetPath;
            set { if (_targetPath != value) { _targetPath = value; OnChanged(); } }
        }

        // ---- remote relay ----
        private bool _remoteEnabled;
        public  bool RemoteEnabled
        {
            get => _remoteEnabled;
            set { if (_remoteEnabled != value) { _remoteEnabled = value; OnChanged(); } }
        }

        private string _remoteHost = "127.0.0.1";
        public  string RemoteHost
        {
            get => _remoteHost;
            set { if (_remoteHost != value) { _remoteHost = value; OnChanged(); } }
        }

        private string _remotePort = "28080";
        public  string RemotePort
        {
            get => _remotePort;
            set { if (_remotePort != value) { _remotePort = value; OnChanged(); } }
        }

        private string _selectedFilter = "All";
        public  string SelectedFilter
        {
            get => _selectedFilter;
            set
            {
                if (_selectedFilter != value)
                {
                    _selectedFilter = value;
                    OnChanged();
                    RebuildVisible();
                }
            }
        }

        // Free-text filter over Function / Args / Ret (case-insensitive).
        private string _searchText = string.Empty;
        public  string SearchText
        {
            get => _searchText;
            set
            {
                value = value ?? string.Empty;
                if (_searchText != value)
                {
                    _searchText = value;
                    OnChanged();
                    RebuildVisible();
                }
            }
        }

        // Show calls from system DLLs too (bypasses the caller noise filter in
        // SharedRingReader). Off by default = only the target's own calls.
        private bool _showSystemCalls;
        public  bool ShowSystemCalls
        {
            get => _showSystemCalls;
            set
            {
                if (_showSystemCalls != value)
                {
                    _showSystemCalls = value;
                    SharedRingReader.ShowSystemCalls = value;
                    OnChanged();
                }
            }
        }

        private bool _isRunning;
        public  bool IsRunning
        {
            get => _isRunning;
            private set
            {
                if (_isRunning != value)
                {
                    _isRunning = value;
                    OnChanged();
                    OnChanged(nameof(CanEditTarget));
                    OnChanged(nameof(RunStopText));
                }
            }
        }

        public bool   CanEditTarget => !IsRunning;
        public string RunStopText   => IsRunning ? "Stop" : "Run";

        private string _statusText = "Ready.";
        public  string StatusText { get => _statusText; set { _statusText = value; OnChanged(); } }

        private string _driverStatus = "Driver: not loaded   Pipe: not started";
        public  string DriverStatus { get => _driverStatus; set { _driverStatus = value; OnChanged(); } }

        public long TotalCount   => _store?.TotalCount   ?? 0;
        public long DroppedCount => _store?.DroppedCount ?? 0;
        public int  VisibleCount => VisibleEvents.Count;

        // ---- commands ----
        private RelayCommand _browseCmd, _runStopCmd, _clearCmd, _browseRemoteCmd;
        public  ICommand BrowseCommand       => _browseCmd  ?? (_browseCmd  = new RelayCommand(DoBrowse));
        public  ICommand RunStopCommand      => _runStopCmd ?? (_runStopCmd = new RelayCommand(DoRunStop));
        public  ICommand ClearCommand        => _clearCmd   ?? (_clearCmd   = new RelayCommand(DoClear));
        public  ICommand BrowseRemoteCommand => _browseRemoteCmd ?? (_browseRemoteCmd = new RelayCommand(DoBrowseRemote));

        // ---- internals ----
        private Window           _ownerWindow;
        private EventStore       _store;
        private DriverClient     _driverClient;
        private Launcher         _launcher;
        private DispatcherTimer  _drainTimer;
        private int              _nextIndex;
        private string           _baseDir;
        private Win32MetadataResolver _winmd;
        private SharedRingReader _ringReader;
        private TargetMemoryReader _memReader;
        private WeirdSyscallDetector _weirdDetector;
        private RemoteClient _remoteClient;

        public void Initialize(Window owner)
        {
            _ownerWindow = owner;
            _baseDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);

            // Event times now come pre-converted to seconds from each target's own
            // TSC base (see SharedRingReader / apimon_proto.h), so there is no
            // GUI-side QPC baseline to capture here anymore.

            _store = new EventStore();

            // Load Win32 metadata (Microsoft.Windows.SDK.Win32Metadata NuGet -
            // copied next to the exe by the build target). Used to rewrite
            // raw "module!Func(0x..., 0x...)" log lines from the Hook DLL
            // into "Func(LPCWSTR lpFileName=0x..., DWORD dwAccess=0x..., ...)".
            try
            {
                string winmdPath = Path.Combine(_baseDir, "Windows.Win32.winmd");
                _winmd = Win32MetadataResolver.Load(winmdPath);
                StatusText = "Loaded " + _winmd.Count + " Win32 API signatures.";
            }
            catch (Exception ex)
            {
                StatusText = "Win32Metadata load failed: " + ex.Message;
                _winmd = null;
            }

            /*
             * Driver is OPTIONAL. Without it user-mode injection (the
             * default for x64dbg / notepad / regular apps) still works.
             * With it we additionally get the kernel-APC fallback for
             * PPL / mitigation-locked targets. If the .sys isn't next to
             * APIMonitor.exe, or it isn't test-signed, or service install
             * fails for any reason - we just continue without it.
             */
            string drvLine = "Driver: off";
            string sysPath = Path.Combine(_baseDir, "APIMonitorDrv.sys");
            if (File.Exists(sysPath))
            {
                try
                {
                    ServiceManager.EnsureInstalledAndStarted(sysPath);
                    if (ServiceManager.IsRunning())
                    {
                        try
                        {
                            _driverClient = new DriverClient();
                            _driverClient.Open();
                            drvLine = "Driver: running";
                        }
                        catch
                        {
                            _driverClient?.Dispose();
                            _driverClient = null;
                            drvLine = "Driver: device open failed";
                        }
                    }
                    else
                    {
                        drvLine = "Driver: not started";
                    }
                }
                catch
                {
                    drvLine = "Driver: signing/install failed";
                }
            }

            DriverStatus = drvLine;

            _drainTimer = new DispatcherTimer(DispatcherPriority.Background)
            {
                Interval = TimeSpan.FromMilliseconds(50)
            };
            _drainTimer.Tick += OnDrainTick;
            _drainTimer.Start();

            // Watchdog: kill the target if system memory drops below the floor.
            // Heavy hook activity used to be able to freeze the host; this is
            // the safety net so a runaway target can't take the OS down.
            _memWatchdogTimer = new DispatcherTimer(DispatcherPriority.Background)
            {
                Interval = TimeSpan.FromMilliseconds(500)
            };
            _memWatchdogTimer.Tick += OnMemoryWatchdogTick;
            _memWatchdogTimer.Start();
        }

        private DispatcherTimer _memWatchdogTimer;
        // If less than this many bytes of RAM is free, abort the run.
        private const ulong LowMemoryThresholdBytes = 300UL * 1024 * 1024;   // 300 MB
        private string _lastFunctionLogged = "<none>";
        private bool   _memAbortFired;

        private void OnMemoryWatchdogTick(object sender, EventArgs e)
        {
            if (!IsRunning || _memAbortFired) return;

            var ms = new NativeMethods.MEMORYSTATUSEX { dwLength = (uint)System.Runtime.InteropServices.Marshal.SizeOf(typeof(NativeMethods.MEMORYSTATUSEX)) };
            if (!NativeMethods.GlobalMemoryStatusEx(ref ms)) return;

            if (ms.ullAvailPhys < LowMemoryThresholdBytes)
            {
                _memAbortFired = true;
                StatusText = "ABORTED: low memory (" + (ms.ullAvailPhys / (1024 * 1024)) +
                             " MB free); last logged: " + _lastFunctionLogged;
                _store?.Enqueue(new ApiEvent
                {
                    Pid = _launcher?.Pid ?? 0,
                    Tid = 0,
                    TimestampQpc = 0,
                    Source = ApimonProto.SOURCE_USER_API,
                    Subcategory = 0,
                    Text = "WATCHDOG ABORT: avail RAM=" + (ms.ullAvailPhys / (1024 * 1024)) +
                           "MB, last logged function: " + _lastFunctionLogged
                });
                try { _launcher?.TryTerminate(); } catch { }
            }
        }

        public void Shutdown()
        {
            try { _drainTimer?.Stop(); } catch { }
            try { _memWatchdogTimer?.Stop(); } catch { }
            try { _launcher?.TryTerminate(); } catch { }
            try { _launcher?.Dispose();  } catch { }
            try { _weirdDetector?.Dispose(); } catch { }
            try { _remoteClient?.Dispose(); } catch { }
            try { _ringReader?.Dispose(); } catch { }
            try { _memReader?.Dispose(); } catch { }
            try { _driverClient?.ClearTarget(); } catch { }
            try { _driverClient?.Dispose(); } catch { }
            try { ServiceManager.TryStop(); } catch { }
        }

        // ---- commands impl ----
        private void DoBrowse()
        {
            var dlg = new OpenFileDialog
            {
                Filter = "Executables (*.exe)|*.exe|All files (*.*)|*.*",
                CheckFileExists = true
            };
            if (dlg.ShowDialog(_ownerWindow) == true)
                TargetPath = dlg.FileName;
        }

        // Open the remote file picker (browses the VM's filesystem via the relay).
        private void DoBrowseRemote()
        {
            if (!int.TryParse(RemotePort, out int port) || port <= 0 || port > 65535)
            {
                MessageBox.Show(_ownerWindow, "Invalid remote port.", "APIMonitor",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            var win = new RemoteBrowseWindow(RemoteHost, port) { Owner = _ownerWindow };
            if (win.ShowDialog() == true && !string.IsNullOrEmpty(win.SelectedPath))
                TargetPath = win.SelectedPath;
        }

        private void DoRunStop()
        {
            if (IsRunning)
            {
                try { _remoteClient?.Dispose(); _remoteClient = null; } catch { }
                try { _launcher?.TryTerminate(); } catch { }
                StopLocalReaders();
                StatusText = "Stopped.";
                IsRunning = false;
            }
            else if (RemoteEnabled)
            {
                LaunchRemote();
            }
            else
            {
                LaunchTarget();
            }
        }

        // Remote mode: connect to an ApimonRelay on the target machine and let
        // it launch + inject there; stream events back into the same store.
        // TargetPath here is the path on the REMOTE machine (typed by hand).
        private void LaunchRemote()
        {
            if (string.IsNullOrWhiteSpace(TargetPath))
            {
                MessageBox.Show(_ownerWindow, "Enter the target .exe path on the remote machine.",
                    "APIMonitor", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            if (!int.TryParse(RemotePort, out int port) || port <= 0 || port > 65535)
            {
                MessageBox.Show(_ownerWindow, "Invalid remote port.", "APIMonitor",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // No local target -> no local memory; args show as types + hex.
            _memReader = null;

            _remoteClient?.Dispose();
            _pendingCalls.Clear();
            _remoteClient = new RemoteClient(_store);
            _remoteClient.Disconnected += reason =>
            {
                Application.Current?.Dispatcher.Invoke(() =>
                {
                    IsRunning = false;
                    StatusText = reason;
                });
            };
            _remoteClient.Start(RemoteHost, port, TargetPath);

            IsRunning = true;
            StatusText = "Remote: connected to " + RemoteHost + ":" + port +
                         ", launching " + TargetPath;
        }

        private void LaunchTarget()
        {
            if (string.IsNullOrWhiteSpace(TargetPath) || !File.Exists(TargetPath))
            {
                MessageBox.Show(_ownerWindow, "Pick an existing .exe first.", "APIMonitor",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            try
            {
                _launcher?.Dispose();
                _launcher = new Launcher(_baseDir, _driverClient, null);
                _launcher.Launch(TargetPath);

                /* Spin up the shared-memory ring reader for this pid. The
                 * Hook DLL inside the target creates "Local\apimon_ring_<pid>"
                 * during DllMain; the reader retries until it appears. */
                _memReader?.Dispose();
                _memReader = new TargetMemoryReader(_launcher.Pid);

                _ringReader?.Dispose();
                _pendingCalls.Clear();
                _ringReader = new SharedRingReader(_store, _launcher.Pid, _memReader);
                _ringReader.Start();

                _weirdDetector?.Dispose();
                _weirdDetector = new WeirdSyscallDetector(_store, _launcher.Pid, _memReader);
                _weirdDetector.Start();

                IsRunning = true;
                StatusText = "Running pid=" + _launcher.Pid + " (" + (_launcher.TargetIs64Bit ? "x64" : "x86") + ")";

                System.Threading.Tasks.Task.Run(() =>
                {
                    uint exitCode = 0;
                    while (!_launcher.TryWaitExit(500, out exitCode)) { }
                    Application.Current?.Dispatcher.Invoke(() =>
                    {
                        StopLocalReaders();
                        IsRunning = false;
                        StatusText = "Target exited (code=" + exitCode + ").";
                    });
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show(_ownerWindow, "Launch failed:\n" + ex.Message, "APIMonitor",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        // Tear down the per-run background readers. Without this, Stop (or a
        // target exit) left the ring/memory/syscall pollers spinning on a dead
        // pid until the next launch or app shutdown.
        private void StopLocalReaders()
        {
            try { _ringReader?.Dispose();   } catch { }
            try { _weirdDetector?.Dispose(); } catch { }
            try { _memReader?.Dispose();    } catch { }
            _ringReader    = null;
            _weirdDetector = null;
            _memReader     = null;
        }

        private void DoClear()
        {
            VisibleEvents.Clear();
            _allEvents.Clear();
            _nextIndex = 0;
            OnChanged(nameof(VisibleCount));
            OnChanged(nameof(TotalCount));
        }

        // ---- event drain ----
        private readonly System.Collections.Generic.List<ApiEventVm> _allEvents =
            new System.Collections.Generic.List<ApiEventVm>(4096);

        private readonly List<ApiEventVm> _drainBatch = new List<ApiEventVm>(512);

        // CALL rows awaiting their RET event, keyed by call_id. A RET fills in
        // the row's Ret column; entries that never get a RET (functions that
        // don't return, or whose RET was dropped) are pruned in bulk if the
        // map grows unreasonably.
        private readonly Dictionary<uint, ApiEventVm> _pendingCalls =
            new Dictionary<uint, ApiEventVm>(4096);

        // If more than this many events arrive per 50 ms tick, switch from per-item
        // Add() to a single AddRange/Reset notification - otherwise the DataGrid
        // re-renders on every Add and the UI freezes.
        private const int BatchThreshold = 30;
        private const int DrainCap       = 2000;

        // Hard ceiling on retained rows. A high-frequency target (e.g. a task
        // manager polling every process) can emit events faster than a human
        // reads them; without a cap the unbounded _allEvents/VisibleEvents
        // lists grow until the GUI exhausts RAM and drags the whole box into
        // swap. When we hit the cap we drop the oldest rows, keeping a recent
        // window. RetentionCap is the max kept; RetentionKeep is what survives
        // a trim.
        private const int RetentionCap  = 400_000;
        private const int RetentionKeep = 200_000;

        // Search-rebuild coalescing (see OnDrainTick).
        private int  _lastSearchRebuild;
        private bool _searchDirty;

        private void OnDrainTick(object sender, EventArgs e)
        {
            if (_store == null) return;

            _drainBatch.Clear();
            int drained = 0;

            while (drained < DrainCap && _store.TryDequeue(out var ev))
            {
                /* RET event: fill in the matching CALL row's return value.
                 * It is not a row of its own. The CALL is always dequeued
                 * before its RET (lower ring seq), so the row exists. */
                if (ev.Kind == ApimonProto.EVKIND_RET)
                {
                    if (_pendingCalls.TryGetValue(ev.CallId, out var callVm))
                    {
                        _pendingCalls.Remove(ev.CallId);
                        string rt = _winmd?.Lookup(callVm.Module, callVm.Function)?.ReturnType;
                        callVm.SetReturnValue(ev.RetValue, rt, _memReader);
                    }
                    drained++;
                    continue;
                }

                var vm = new ApiEventVm(_nextIndex++, ev, ev.Seconds, _winmd, _memReader);
                _allEvents.Add(vm);

                /* Only real API CALL rows can receive a RET. Text/driver
                 * events (Args == null) never do, so keep them out of the map. */
                if (ev.Args != null)
                {
                    if (_pendingCalls.Count > 200_000) _pendingCalls.Clear();
                    _pendingCalls[vm.CallId] = vm;
                }

                if (PassesFilter(vm))
                    _drainBatch.Add(vm);
                /* track for the memory watchdog so we know what the target was doing if it tanks */
                if (!string.IsNullOrEmpty(vm.Function)) _lastFunctionLogged = vm.Function;
                drained++;
            }

            // With an active search the incremental add can't account for Ret
            // values that arrive (and may match) after their CALL row was
            // already filtered out, so re-scan instead. Without a search we
            // add incrementally for a live feel.
            if (_searchText.Length > 0)
            {
                // A full re-scan (up to RetentionCap rows) every 50 ms tick froze
                // the UI under load. Coalesce: rebuild at most ~5x/sec, and always
                // flush the final state within one window of the last event.
                if (drained > 0) _searchDirty = true;
                if (_searchDirty && Environment.TickCount - _lastSearchRebuild >= 200)
                {
                    RebuildVisible();
                    _lastSearchRebuild = Environment.TickCount;
                    _searchDirty = false;
                }
            }
            else if (_drainBatch.Count > 0)
            {
                if (_drainBatch.Count <= BatchThreshold)
                {
                    // Few events - insert one by one for "live" feel.
                    foreach (var vm in _drainBatch)
                        VisibleEvents.Add(vm);
                }
                else
                {
                    // Burst - one Reset to keep the UI responsive.
                    VisibleEvents.AddRange(_drainBatch);
                }
            }

            if (_allEvents.Count > RetentionCap)
                TrimRetention();

            if (drained > 0)
            {
                OnChanged(nameof(TotalCount));
                OnChanged(nameof(DroppedCount));
                OnChanged(nameof(VisibleCount));
            }
        }

        // Drop the oldest rows down to RetentionKeep so memory stays bounded
        // regardless of how fast the target emits events. Pending CALL->RET
        // matches for dropped rows are abandoned (their Ret just stays blank).
        private void TrimRetention()
        {
            int drop = _allEvents.Count - RetentionKeep;
            if (drop <= 0) return;
            _allEvents.RemoveRange(0, drop);
            _pendingCalls.Clear();
            RebuildVisible();
            StatusText = "Trimmed " + drop + " old events (memory cap " + RetentionCap + ").";
        }

        private bool PassesFilter(ApiEventVm vm)
        {
            bool sourceOk;
            switch (_selectedFilter)
            {
                case "User-mode (API)": sourceOk = vm.Source == ApimonProto.SOURCE_USER_API; break;
                case "User-mode (COM)": sourceOk = vm.Source == ApimonProto.SOURCE_USER_COM; break;
                default:                sourceOk = true; break;
            }
            if (!sourceOk) return false;

            if (_searchText.Length == 0) return true;
            return Contains(vm.Function, _searchText)
                || Contains(vm.Ret,      _searchText)
                || Contains(vm.Args,     _searchText);
        }

        private static bool Contains(string haystack, string needle)
        {
            return !string.IsNullOrEmpty(haystack)
                && haystack.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private void RebuildVisible()
        {
            var batch = new List<ApiEventVm>(_allEvents.Count);
            foreach (var v in _allEvents)
                if (PassesFilter(v))
                    batch.Add(v);
            VisibleEvents.Clear();
            VisibleEvents.AddRange(batch);
            OnChanged(nameof(VisibleCount));
        }

        // ---- INPC ----
        public event PropertyChangedEventHandler PropertyChanged;
        private void OnChanged([CallerMemberName] string name = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
