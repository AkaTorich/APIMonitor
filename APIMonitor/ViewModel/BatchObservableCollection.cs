using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;

namespace APIMonitor.ViewModel
{
    /// <summary>
    /// ObservableCollection that supports AddRange with a single Reset notification.
    /// Standard ObservableCollection.Add fires per-item CollectionChanged events,
    /// which forces WPF DataGrid to re-render after every insertion. Adding
    /// hundreds of items per timer tick freezes the UI thread. AddRange here
    /// inserts in bulk and fires one Reset, which the DataGrid handles in O(visible-rows).
    /// </summary>
    public sealed class BatchObservableCollection<T> : ObservableCollection<T>
    {
        public void AddRange(IList<T> items)
        {
            if (items == null || items.Count == 0) return;

            CheckReentrancy();
            foreach (var it in items) Items.Add(it);
            OnPropertyChanged(new PropertyChangedEventArgs(nameof(Count)));
            OnPropertyChanged(new PropertyChangedEventArgs("Item[]"));
            OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
        }

        public new void Clear()
        {
            CheckReentrancy();
            Items.Clear();
            OnPropertyChanged(new PropertyChangedEventArgs(nameof(Count)));
            OnPropertyChanged(new PropertyChangedEventArgs("Item[]"));
            OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
        }
    }
}
