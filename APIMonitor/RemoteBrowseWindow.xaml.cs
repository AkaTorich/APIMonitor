using System;
using System.Windows;
using System.Windows.Input;
using APIMonitor.Services;

namespace APIMonitor
{
    /// <summary>
    /// Remote file picker. Talks to an ApimonRelay on the VM to browse its
    /// filesystem and pick an .exe to launch. On OK, <see cref="SelectedPath"/>
    /// holds the chosen path AS IT IS ON THE REMOTE MACHINE.
    /// </summary>
    public partial class RemoteBrowseWindow : Window
    {
        private readonly RemoteBrowserClient _client = new RemoteBrowserClient();
        private string _cur = string.Empty;   // "" = drive roots

        public string SelectedPath { get; private set; }

        public RemoteBrowseWindow(string host, int port)
        {
            InitializeComponent();

            bool connected = false;
            try { _client.Connect(host, port); connected = true; }
            catch (Exception ex)
            {
                MessageBox.Show(this, "Connect to relay failed: " + ex.Message,
                    "Remote browse", MessageBoxButton.OK, MessageBoxImage.Error);
            }

            Loaded  += (s, e) => { if (connected) Navigate(string.Empty); };
            Closed  += (s, e) => _client.Dispose();
        }

        private void Navigate(string path)
        {
            try
            {
                var entries = _client.List(path, out string err);
                if (err != null)
                {
                    MessageBox.Show(this, err, "Remote browse",
                        MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;   // stay where we are
                }
                _cur = path;
                PathBox.Text = string.IsNullOrEmpty(path) ? "(drives)" : path;
                List.ItemsSource = entries;
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "List failed: " + ex.Message, "Remote browse",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private static string Combine(string cur, string name)
        {
            if (string.IsNullOrEmpty(cur)) return name;        // root entries are full ("C:\")
            if (cur.EndsWith("\\")) return cur + name;
            return cur + "\\" + name;
        }

        private static string Parent(string cur)
        {
            if (string.IsNullOrEmpty(cur)) return string.Empty;
            string t = cur.TrimEnd('\\');
            int i = t.LastIndexOf('\\');
            if (i < 0) return string.Empty;                    // "C:" -> drives
            return t.Substring(0, i + 1);                      // keep trailing backslash
        }

        private void OpenSelected()
        {
            var e = List.SelectedItem as RemoteEntry;
            if (e == null) return;
            if (e.IsDir) { Navigate(Combine(_cur, e.Name)); return; }
            SelectedPath = Combine(_cur, e.Name);
            DialogResult = true;
            Close();
        }

        private void List_DoubleClick(object sender, MouseButtonEventArgs e) => OpenSelected();
        private void Open_Click(object sender, RoutedEventArgs e)            => OpenSelected();
        private void Up_Click(object sender, RoutedEventArgs e)              => Navigate(Parent(_cur));
        private void Cancel_Click(object sender, RoutedEventArgs e)          { DialogResult = false; Close(); }
        private void Close_Click(object sender, RoutedEventArgs e)           { DialogResult = false; Close(); }
    }
}
