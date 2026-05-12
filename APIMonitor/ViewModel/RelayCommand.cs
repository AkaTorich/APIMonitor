using System;
using System.Windows.Input;

namespace APIMonitor.ViewModel
{
    /// <summary>
    /// Standard relay-command implementation - keeps us off MVVM toolkits.
    /// </summary>
    public sealed class RelayCommand : ICommand
    {
        private readonly Action      _execute;
        private readonly Func<bool>  _canExecute;

        public RelayCommand(Action execute, Func<bool> canExecute = null)
        {
            _execute = execute ?? throw new ArgumentNullException(nameof(execute));
            _canExecute = canExecute;
        }

        public bool CanExecute(object parameter) => _canExecute?.Invoke() ?? true;
        public void Execute(object parameter)    => _execute();

        public event EventHandler CanExecuteChanged
        {
            add    { CommandManager.RequerySuggested += value; }
            remove { CommandManager.RequerySuggested -= value; }
        }

        public void RaiseCanExecuteChanged() => CommandManager.InvalidateRequerySuggested();
    }
}
