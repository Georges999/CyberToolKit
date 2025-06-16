using SharpPcap;
using System;
using System.Collections.ObjectModel;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using CyberUtils; // Required for PacketSnifferService

namespace CyberToolKit
{
    public class CapturedPacket
    {
        public DateTime Timestamp { get; set; }
        public string SourceIp { get; set; } = "";
        public string DestinationIp { get; set; } = "";
        public string Protocol { get; set; } = "";
        public int Length { get; set; }
        public string Info { get; set; } = "";
    }

    public partial class PacketSnifferView : UserControl
    {
        public ObservableCollection<CapturedPacket> Packets { get; set; }
        private readonly PacketSnifferService _snifferService;
        private CancellationTokenSource? _cancellationTokenSource;

        public PacketSnifferView()
        {
            InitializeComponent();
            Packets = new ObservableCollection<CapturedPacket>();
            PacketListView.ItemsSource = Packets;
            _snifferService = new PacketSnifferService(); // Now valid
            _snifferService.PacketCaptured += OnPacketCaptured;
            Loaded += PacketSnifferView_Loaded;
            Unloaded += PacketSnifferView_Unloaded;
        }

        private void OnPacketCaptured(CapturedPacket packet)
        {
            Dispatcher.Invoke(() =>
            {
                Packets.Insert(0, packet);
                if (Packets.Count > 200)
                {
                    Packets.RemoveAt(Packets.Count - 1);
                }
            });
        }

        private void PacketSnifferView_Loaded(object sender, RoutedEventArgs e)
        {
            RefreshInterfaces();
        }

        private void PacketSnifferView_Unloaded(object sender, RoutedEventArgs e)
        {
            StopCapture();
        }

        private void RefreshInterfaces()
        {
            try
            {
                var devices = CaptureDeviceList.Instance;
                if (devices.Count == 0)
                {
                    StatusText.Text = "No network interfaces found. Make sure Npcap is installed.";
                    return;
                }
                InterfaceComboBox.ItemsSource = devices;
                InterfaceComboBox.DisplayMemberPath = "Description";
                if (devices.Count > 0) InterfaceComboBox.SelectedIndex = 0;
            }
            catch (Exception ex)
            {
                StatusText.Text = $"Error loading interfaces: {ex.Message}";
            }
        }

        private void StartButton_Click(object sender, RoutedEventArgs e)
        {
            if (InterfaceComboBox.SelectedItem is not ICaptureDevice selectedDevice)
            {
                StatusText.Text = "Please select a network interface.";
                return;
            }

            StartButton.IsEnabled = false;
            StopButton.IsEnabled = true;
            InterfaceComboBox.IsEnabled = false;
            RefreshButton.IsEnabled = false;
            StatusText.Text = $"Capture started on {selectedDevice.Description}...";
            Packets.Clear();

            _cancellationTokenSource = new CancellationTokenSource();
            var token = _cancellationTokenSource.Token;

            Task.Run(() => _snifferService.Start(selectedDevice, token), token);
        }

        private void StopButton_Click(object sender, RoutedEventArgs e)
        {
            StopCapture();
        }

        private void StopCapture()
        {
            if (_cancellationTokenSource != null && !_cancellationTokenSource.IsCancellationRequested)
            {
                _cancellationTokenSource.Cancel();
                _cancellationTokenSource.Dispose();
                _cancellationTokenSource = null;
            }

            StartButton.IsEnabled = true;
            StopButton.IsEnabled = false;
            InterfaceComboBox.IsEnabled = true;
            RefreshButton.IsEnabled = true;
            StatusText.Text = "Capture stopped.";
        }

        private void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            if (StartButton.IsEnabled)
            {
                RefreshInterfaces();
            }
        }
    }
}
