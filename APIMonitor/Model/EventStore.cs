using System.Collections.Concurrent;
using System.Threading;

namespace APIMonitor.Model
{
    /// <summary>
    /// Lock-free intake queue for events arriving from background threads (pipe + driver IO).
    /// The UI thread drains it on a dispatcher timer (see MainViewModel).
    /// </summary>
    public sealed class EventStore
    {
        private readonly ConcurrentQueue<ApiEvent> _queue = new ConcurrentQueue<ApiEvent>();
        private long _droppedCount;
        private long _totalCount;

        public long TotalCount   => Interlocked.Read(ref _totalCount);
        public long DroppedCount => Interlocked.Read(ref _droppedCount);

        /// <summary>Maximum number of buffered (not yet drained) events. Prevents OOM if UI lags.</summary>
        public int MaxBuffered { get; set; } = 200_000;

        public void Enqueue(ApiEvent ev)
        {
            if (_queue.Count >= MaxBuffered)
            {
                Interlocked.Increment(ref _droppedCount);
                return;
            }
            _queue.Enqueue(ev);
            Interlocked.Increment(ref _totalCount);
        }

        public bool TryDequeue(out ApiEvent ev) => _queue.TryDequeue(out ev);

        public int CurrentBuffered => _queue.Count;
    }
}
