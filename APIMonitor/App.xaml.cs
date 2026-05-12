using System;
using System.Windows;
using System.Windows.Threading;

namespace APIMonitor
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            // Catch any unhandled exception on the dispatcher so the app doesn't die silently.
            DispatcherUnhandledException += OnDispatcherUnhandledException;
            AppDomain.CurrentDomain.UnhandledException += OnDomainUnhandledException;
            base.OnStartup(e);
        }

        private static void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
        {
            MessageBox.Show(
                "Unhandled UI exception:\n\n" + e.Exception,
                "APIMonitor",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            e.Handled = true;
        }

        private static void OnDomainUnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            var ex = e.ExceptionObject as Exception;
            MessageBox.Show(
                "Unhandled background exception:\n\n" + (ex != null ? ex.ToString() : "?"),
                "APIMonitor",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }
}
