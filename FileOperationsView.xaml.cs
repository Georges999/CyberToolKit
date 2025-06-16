using CyberUtils;
using Microsoft.Extensions.Configuration;
using Microsoft.Win32;
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

namespace CyberToolKit
{
    public partial class FileOperationsView : UserControl
    {
        private FileOperationsService? _fileOpsService;
        private string _currentDirectory;

        public FileOperationsView()
        {
            InitializeComponent();
            Loaded += FileOperationsView_Loaded;
        }

        private void FileOperationsView_Loaded(object sender, RoutedEventArgs e)
        {
            var app = (App)Application.Current;
            if (app.Configuration == null) return;

            var settings = app.Configuration.GetSection("FileOperations").Get<FileOperationsSettings>();
            if (settings != null)
            {
                _currentDirectory = settings.TargetDirectory;
                _fileOpsService = new FileOperationsService(settings);
                RefreshFileList();
            }
        }

        private void RefreshFileList()
        {
            if (_fileOpsService == null) return;

            try
            {
                var files = _fileOpsService.GetAllFilesRecursive()
                    .Select(f => new { Name = Path.GetFileName(f), Size = new FileInfo(f).Length });
                FileListView.ItemsSource = files;
                StatusText.Text = $"Listing files in: {_currentDirectory}";
            }
            catch (Exception ex)
            {
                StatusText.Text = $"Error: {ex.Message}";
            }
        }

        private async void EncryptButton_Click(object sender, RoutedEventArgs e)
        {
            if (_fileOpsService == null) return;

            StatusText.Text = "Encrypting... please wait.";
            await Task.Run(() => _fileOpsService.EncryptFiles());
            StatusText.Text = "Encryption complete.";
            RefreshFileList();
        }

        private async void DecryptButton_Click(object sender, RoutedEventArgs e)
        {
            if (_fileOpsService == null) return;

            StatusText.Text = "Decrypting... please wait.";
            await Task.Run(() => _fileOpsService.DecryptFiles());
            StatusText.Text = "Decryption complete.";
            RefreshFileList();
        }

        private void ChangeDirButton_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFolderDialog
            {
                Title = "Select a new directory for file operations"
            };

            if (dialog.ShowDialog() == true)
            {
                _currentDirectory = dialog.FolderName;
                var app = (App)Application.Current;
                if (app.Configuration != null)
                {
                    var settings = app.Configuration.GetSection("FileOperations").Get<FileOperationsSettings>() ?? new FileOperationsSettings();
                    settings.TargetDirectory = _currentDirectory;
                    _fileOpsService = new FileOperationsService(settings);
                    RefreshFileList();
                }
            }
        }

        private void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            RefreshFileList();
        }
    }
}
