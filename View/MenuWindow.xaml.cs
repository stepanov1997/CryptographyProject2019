using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using CryptographyProject2019.Controller;

namespace CryptographyProject2019.View
{
    /// <summary>
    ///     Interaction logic for MenuWindow.xaml
    /// </summary>
    public partial class MenuWindow : Window
    {
        private readonly Window _previousWindow;

        public MenuWindow(Window previousWindow)
        {
            _previousWindow = previousWindow;
            InitializeComponent();
            ImeLabel.Content = ImeLabel.Content + Environment.NewLine +
                               AccountsController.GetInstance().CurrentAccount.Username;
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            var mw = new MainWindow();
            mw.Show();
            Hide();
        }

        private void FileEncryptionClick(object sender, RoutedEventArgs e)
        {
            var few = new FileEncryptionWindow(this);
            few.Show();
            Hide();
        }

        protected override void OnClosing(CancelEventArgs e)
        {
            File.Delete(Directory.GetCurrentDirectory() + "/../../CurrentUser/private.key");
            Process.GetCurrentProcess().Kill();
            base.OnClosing(e);
        }

        private void FileDecryptionValidationClick(object sender, RoutedEventArgs e)
        {
            var fdv = new FileDecryptionValidationWindow(this);
            fdv.Show();
            Hide();
        }
    }
}