using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using Microsoft.Extensions.Configuration;

namespace CyberToolKit
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            var app = (App)System.Windows.Application.Current;
            if (app.Configuration != null)
            {
                string? targetDirectory = app.Configuration.GetSection("FileOperations")["TargetDirectory"];
                CurrentDirectoryText.Text = $"Working Directory: {targetDirectory}";
            }
        }

        private void MenuList_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            if (MenuList.SelectedItem is System.Windows.Controls.ListBoxItem selectedItem && selectedItem.Content != null)
            {
                string selection = selectedItem.Content.ToString() ?? "";
                var viewTitle = new System.Windows.Controls.TextBlock 
                { 
                    Text = $"{selection} View Loaded", 
                    Foreground = System.Windows.Media.Brushes.White, 
                    FontSize = 24, 
                    HorizontalAlignment = HorizontalAlignment.Center, 
                    VerticalAlignment = VerticalAlignment.Center 
                };

                switch (selection)
                {
                    case "Dashboard":
                        MainContent.Content = new System.Windows.Controls.TextBlock { Text = "Welcome to CyberToolKit", FontSize = 32, FontWeight = FontWeights.Light, Foreground = System.Windows.Media.Brushes.White, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
                        break;
                    case "Packet Sniffer":
                        MainContent.Content = new PacketSnifferView();
                        break;
                    case "Nmap Scanner":
                    case "Honeypot":
                        MainContent.Content = viewTitle; // Placeholder for now
                        break;
                    case "Encrypt File":
                    case "Decrypt File":
                    case "Change Directory":
                        MainContent.Content = new FileOperationsView();
                        break;
                    case "Integrity Checker":
                        MainContent.Content = viewTitle; // Placeholder for now
                        break;
                    default:
                        MainContent.Content = new System.Windows.Controls.TextBlock { Text = "Welcome to CyberToolKit", FontSize = 32, FontWeight = FontWeights.Light, Foreground = System.Windows.Media.Brushes.White, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
                        break;
                }
            }
        }
    }
}
