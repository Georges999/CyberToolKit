using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using CyberUtils.Modules;
using Encryption_malware;

namespace CyberUtils
{
    class Program
    {
        private static AppSettings? _appSettings;
        private static HoneypotService? _honeypotService;
        private static Task? _honeypotTask;
                private static string _currentDirectory = string.Empty;
        private static IConfigurationRoot? _configuration;
        private static NmapService? _nmapService;

        static async Task Main(string[] args)
        {
            Console.Title = "Cyber Utils Toolkit";
            LoadConfiguration();

            // Exit if configuration failed critically
            if (_appSettings == null || string.IsNullOrWhiteSpace(_appSettings.FileOperations.TargetDirectory) || string.IsNullOrWhiteSpace(_appSettings.FileOperations.EncryptionKey))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\nCritical configuration missing (TargetDirectory, EncryptionKey). Please check appsettings.json.");
                Console.ResetColor();
                Console.WriteLine("Press any key to exit...");
                Console.ReadKey();
                return;
            }

            // Initialize current directory from settings
            _currentDirectory = _appSettings.FileOperations.TargetDirectory;

            // Instantiate services (handle potential config issues within services)
            FileOperationsService? fileOpsService = null;
            IntegrityCheckerService? integrityCheckerService = null;

            try { fileOpsService = new FileOperationsService(_appSettings.FileOperations); }
            catch (ArgumentException ex) { PrintError($"File Operations setup failed: {ex.Message}"); }

            try { _honeypotService = new HoneypotService(_appSettings.Honeypot); }
            catch (ArgumentException ex) { PrintError($"Honeypot setup failed: {ex.Message}"); }

                        try { integrityCheckerService = new IntegrityCheckerService(_appSettings.IntegrityChecker); }
            catch (ArgumentException ex) { PrintError($"Integrity Checker setup failed: {ex.Message}"); }

            try
            {
                _nmapService = new NmapService(_appSettings.Nmap);
                Console.WriteLine("Nmap service initialized.");
            }
            catch (Exception)
            {
                PrintError("Nmap service setup failed. Ensure Nmap is installed and in your system's PATH.");
            }

            // Main application loop for dashboard
            await RunDashboardLoop(fileOpsService, integrityCheckerService);

            // Ensure honeypot stops on exit
            if (_honeypotService?.IsRunning ?? false)
            {
                _honeypotService.Stop();
                if (_honeypotTask != null) await _honeypotTask; // Wait for task to complete if running
            }

            Console.WriteLine("\nExiting Toolkit. Goodbye!");
        }

        static void LoadConfiguration()
        {
            Console.WriteLine("Loading configuration from appsettings.json...");
            try
            {
                var builder = new ConfigurationBuilder()
                    .SetBasePath(Directory.GetCurrentDirectory())
                    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);

                _configuration = builder.Build();

                _appSettings = new AppSettings();
                _configuration.Bind(_appSettings);

                if (_appSettings?.FileOperations?.EncryptionKey == "!!REPLACE_THIS_WITH_A_STRONG_KEY!!")
                {
                    PrintWarning("SECURITY WARNING: Default encryption key found in appsettings.json! Replace it with a strong, unique key and protect the configuration file.");
                }
                Console.WriteLine("Configuration loaded.");
            }
            catch (FileNotFoundException)
            {
                PrintError("Error: appsettings.json not found in the application directory.");
                _appSettings = null;
            }
            catch (Exception ex)
            {
                PrintError($"Error loading configuration: {ex.Message}");
                _appSettings = null;
            }
        }

        static async Task RunDashboardLoop(FileOperationsService? fileOps, IntegrityCheckerService? integrityChecker)
        {
            bool keepRunning = true;
            while (keepRunning)
            {
                PrintDashboardMenu();
                string? choice = Console.ReadLine();

                switch (choice?.ToLower())
                {
                    case "1": // Find Files
                        if (fileOps != null)
                        {
                            // Use updated settings with current directory
                            var settings = new FileOperationsSettings
                            {
                                TargetDirectory = _currentDirectory,
                                EncryptionKey = _appSettings?.FileOperations?.EncryptionKey ?? string.Empty,
                                TempDirectory = _appSettings?.FileOperations?.TempDirectory ?? string.Empty
                            };
                            var tempService = new FileOperationsService(settings);
                            tempService.FindAndDisplayFiles();
                        }
                        else
                        {
                            PrintError("File Operations module not initialized.");
                        }
                        break;
                        
                    case "2": // Encrypt Files
                        if (fileOps != null)
                        {
                            PrintWarning("This will encrypt all files in the current directory and is irreversible without the key.");
                            PrintWarning($"Current directory: {_currentDirectory}");
                            PrintWarning("Type 'CONFIRM' to proceed:");
                            
                            if (Console.ReadLine() == "CONFIRM")
                            {
                                var settings = new FileOperationsSettings
                                {
                                    TargetDirectory = _currentDirectory,
                                    EncryptionKey = _appSettings?.FileOperations?.EncryptionKey ?? string.Empty,
                                    TempDirectory = _appSettings?.FileOperations?.TempDirectory ?? string.Empty
                                };
                                
                                var tempService = new FileOperationsService(settings);
                                
                                try
                                {
                                    tempService.EncryptFiles();
                                    Console.WriteLine("Directory encryption completed.");
                                }
                                catch (Exception ex)
                                {
                                    PrintError($"Directory encryption failed: {ex.Message}");
                                }
                            }
                            else
                            {
                                Console.WriteLine("Encryption cancelled.");
                            }
                        }
                        else
                        {
                            PrintError("File Operations module not initialized.");
                        }
                        break;
                        
                    case "3": // Decrypt Files
                        if (fileOps != null)
                        {
                            PrintWarning("This will decrypt all encrypted files in the current directory.");
                            PrintWarning($"Current directory: {_currentDirectory}");
                            
                            var settings = new FileOperationsSettings
                            {
                                TargetDirectory = _currentDirectory,
                                EncryptionKey = _appSettings?.FileOperations?.EncryptionKey ?? string.Empty,
                                TempDirectory = _appSettings?.FileOperations?.TempDirectory ?? string.Empty
                            };
                            
                            var tempService = new FileOperationsService(settings);
                            
                            try
                            {
                                tempService.DecryptFiles();
                            }
                            catch (Exception ex)
                            {
                                PrintError($"Directory decryption failed: {ex.Message}");
                            }
                        }
                        else
                        {
                            PrintError("File Operations module not initialized.");
                        }
                        break;
                        
                    case "4": // Start Honeypot
                        if (_honeypotService != null && !_honeypotService.IsRunning)
                        {
                            Console.WriteLine("Starting honeypot asynchronously...");
                            _honeypotTask = _honeypotService.StartAsync();
                        }
                        else if (_honeypotService?.IsRunning ?? false)
                        {
                            PrintWarning("Honeypot is already running.");
                        }
                        else
                        {
                            PrintError("Honeypot module not initialized.");
                        }
                        break;
                        
                    case "5": // Stop Honeypot
                        if (_honeypotService?.IsRunning ?? false)
                        {
                            Console.WriteLine("Stopping honeypot...");
                            _honeypotService.Stop();
                            if (_honeypotTask != null && !_honeypotTask.IsCompleted)
                            {
                                Console.WriteLine("Waiting for honeypot task to stop...");
                                await _honeypotTask;
                                _honeypotTask = null;
                            }
                        }
                        else
                        {
                            PrintWarning("Honeypot is not running.");
                        }
                        break;
                        
                    case "6": // Create Integrity Baseline
                        if (integrityChecker != null)
                        {
                            // Use current directory for integrity checker
                            var settings = new IntegrityCheckerSettings
                            {
                                BaselineFilePath = _appSettings?.IntegrityChecker?.BaselineFilePath ?? "file_integrity_baseline.json",
                                DirectoryToMonitor = _currentDirectory
                            };
                            var tempService = new IntegrityCheckerService(settings);
                            tempService.CreateBaseline();
                        }
                        else
                        {
                            PrintError("Integrity Checker module not initialized.");
                        }
                        break;
                        
                    case "7": // Verify Integrity
                        if (integrityChecker != null)
                        {
                            // Use current directory for integrity checker
                            var settings = new IntegrityCheckerSettings
                            {
                                BaselineFilePath = _appSettings?.IntegrityChecker?.BaselineFilePath ?? "file_integrity_baseline.json",
                                DirectoryToMonitor = _currentDirectory
                            };
                            var tempService = new IntegrityCheckerService(settings);
                            tempService.VerifyIntegrity();
                        }
                        else
                        {
                            PrintError("Integrity Checker module not initialized.");
                        }
                        break;
                        
                    case "8": // Select Working Directory
                        SelectWorkingDirectory();
                        break;
                        
                   case "9": // Packet Sniffer
    if (_configuration != null)
    {
        var sec = _configuration.GetSection("PacketSniffer");
        string iface = sec["InterfaceName"] ?? "Ethernet";
        int duration = int.Parse(sec["CaptureDurationMs"] ?? "5000");
        
        Console.WriteLine("\n=== Network Packet Sniffer ===");
        Console.WriteLine("1. Quick scan (default settings)");
        Console.WriteLine("2. Full scan with website tracking");
        Console.WriteLine("3. Choose interface and settings");
         Console.WriteLine("4. Monitor all WiFi network devices");
        Console.Write("\nSelect option: ");
        
        string snifferOption = Console.ReadLine() ?? "1";
        
        switch (snifferOption)
        {
            case "2":
                // Full website tracking
                var captureFile = Path.Combine(Directory.GetCurrentDirectory(), "capture.pcap");
                var sniffer = new PacketSnifferService(iface, 30000, captureFile);
                sniffer.Run();
                break;
                
            case "3":
                // List available interfaces
                Console.WriteLine("Listing available interfaces...");
                try
                {
                    var devices = SharpPcap.CaptureDeviceList.Instance;
                    if (devices.Count == 0)
                    {
                        Console.WriteLine("No capture devices found. Please install Npcap.");
                        break;
                    }
                    
                    Console.WriteLine("\nAvailable interfaces:");
                    for (int i = 0; i < devices.Count; i++)
                    {
                        Console.WriteLine($"{i+1}. {devices[i].Description}");
                    }
                    
                    Console.Write("\nSelect interface (number): ");
                    if (int.TryParse(Console.ReadLine(), out int devNum) && devNum > 0 && devNum <= devices.Count)
                    {
                        string selectedIface = devices[devNum - 1].Name;
                        
                        Console.Write("Enter capture duration (seconds): ");
                        if (int.TryParse(Console.ReadLine(), out int capDuration) && capDuration > 0)
                        {
                            Console.Write("Save packets to file? (y/n): ");
                            bool saveToFile = Console.ReadLine()?.ToLower() == "y";
                            
                            string? capFile = saveToFile ? 
                                Path.Combine(Directory.GetCurrentDirectory(), "capture.pcap") : null;
                            
                            var customSniffer = new PacketSnifferService(selectedIface, capDuration * 1000, capFile);
                            customSniffer.Run();
                        }
                    }
                }
                catch (DllNotFoundException)
                {
                    PrintError("Missing packet capture drivers. Please install Npcap.");
                }
                catch (Exception ex)
                {
                    PrintError($"Error: {ex.Message}");
                }
                break;

                  case "4":
                // WiFi monitoring mode
                PrintWarning("WiFi monitoring captures data about connected devices");
                PrintWarning("Note that full packet contents between other devices will be encrypted");
                Console.WriteLine("Enter monitoring duration in seconds (10-120): ");
                
                if (int.TryParse(Console.ReadLine(), out int monitorDuration) && 
                    monitorDuration >= 10 && monitorDuration <= 120)
                {
                    
                    var monitorSniffer = new PacketSnifferService(iface, monitorDuration * 1000);
                    monitorSniffer.RunWifiMonitor(captureAllDevices: true);
                }
                else
                {
                    Console.WriteLine("Using default duration of 30 seconds");
                    var monitorSniffer = new PacketSnifferService(iface, 30000);
                    monitorSniffer.RunWifiMonitor(captureAllDevices: true);
                }
                break;
                
            default:
                // Quick scan
                var quickSniffer = new PacketSnifferService(iface, duration);
                quickSniffer.Run();
                break;
        }
    }
    else
    {
        PrintError("Configuration not loaded properly");
    }
    break;
                        
                    case "10": // WiFi Honeypot
                        if (_configuration != null)
                        {
                            var wifiSettings = new CyberUtils.Modules.WifiHoneypotSettings
                            {
                                LogFilePath = "wifi_honeypot.log",
                                FakeAccessPointSettings = new CyberUtils.Modules.FakeAccessPointSettings
                                {
                                    Ssid = "Free_Public_WiFi",
                                    Channel = 6,
                                    SecurityType = "WPA2",
                                    Password = "password123"
                                },
                                NetworkSettings = new CyberUtils.Modules.NetworkSettings
                                {
                                    DhcpIpRange = "192.168.100.100-200",
                                    SubnetMask = "255.255.255.0",
                                    Gateway = "192.168.100.1"
                                },
                                CaptureSettings = new CyberUtils.Modules.CaptureSettings
                                {
                                    InterfaceName = "Wi-Fi"
                                }
                            };
                            
                            var wifiHoneypot = new CyberUtils.Modules.RealWifiHoneypotModule(wifiSettings);
                            
                            Console.WriteLine("\nWiFi Honeypot Control");
                            Console.WriteLine("1. Start WiFi Honeypot");
                            Console.WriteLine("2. Stop WiFi Honeypot");
                            Console.WriteLine("0. Back to main menu");
                            Console.Write("Enter choice: ");
                            
                            string? subChoice = Console.ReadLine();
                            switch (subChoice)
                            {
                                case "1":
                                    Console.WriteLine("Starting WiFi Honeypot...");
                                    await wifiHoneypot.StartAsync();
                                    break;
                                case "2":
                                    Console.WriteLine("Stopping WiFi Honeypot...");
                                    await wifiHoneypot.StopAsync();
                                    break;
                            }
                        }
                        break;
                        
                    case "11": // Advanced Nmap Reconnaissance
                        if (_nmapService != null)
                        {
                            try
                            {
                                await _nmapService.RunInteractiveScanAsync();
                            }
                            catch (Exception ex)
                            {
                                PrintError($"Nmap reconnaissance failed: {ex.Message}");
                            }
                        }
                        else
                        {
                            PrintError("Nmap service not initialized. Ensure Nmap is installed and in your system's PATH.");
                        }
                        break;

                    case "0":
                    case "q":
                    case "exit":
                        keepRunning = false;
                        break;
                        
                    default:
                        PrintWarning("Invalid choice. Please try again.");
                        break;
                }

                if (keepRunning)
                {
                    Console.WriteLine("\nPress Enter to return to the dashboard...");
                    Console.ReadLine();
                }
            }
        }

        static void SelectWorkingDirectory()
        {
            Console.Clear();
            Console.WriteLine("=== Select Working Directory ===");
            Console.WriteLine($"Current working directory: {_currentDirectory}");
            Console.WriteLine("\nEnter new directory path (or press Enter to cancel):");
            string? input = Console.ReadLine();

            if (string.IsNullOrWhiteSpace(input))
            {
                Console.WriteLine("Operation cancelled, keeping current directory.");
                return;
            }

            // Validate the directory exists
            if (Directory.Exists(input))
            {
                _currentDirectory = input;
                Console.WriteLine($"Working directory changed to: {_currentDirectory}");
            }
            else
            {
                // Try to create directory if it doesn't exist
                try
                {
                    Directory.CreateDirectory(input);
                    _currentDirectory = input;
                    Console.WriteLine($"Directory created and working directory changed to: {_currentDirectory}");
                }
                catch (Exception ex)
                {
                    PrintError($"Could not create directory: {ex.Message}");
                }
            }
        }

        static void PrintDashboardMenu()
        {
            Console.Clear(); // Clear screen for a fresh menu
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("=============================");
            Console.WriteLine("   Cyber Utils Toolkit Menu");
            Console.WriteLine("=============================");
            Console.WriteLine($"Current Directory: {_currentDirectory}");
            Console.WriteLine("=============================");
            Console.ResetColor();
            Console.WriteLine("--- File Operations ---");
            Console.WriteLine(" 1. Find Files");
            Console.WriteLine(" 2. Encrypt Files (Warning!)");
            Console.WriteLine(" 3. Decrypt Files");
            Console.WriteLine("--- Network Monitoring ---");
            Console.WriteLine($" 4. Start Honeypot (Port: {_appSettings?.Honeypot.ListenPort}) [Status: {(_honeypotService?.IsRunning ?? false ? "Running" : "Stopped")}]");
            Console.WriteLine(" 5. Stop Honeypot");
            Console.WriteLine("--- File Integrity ---");
            Console.WriteLine(" 6. Create Integrity Baseline");
            Console.WriteLine(" 7. Verify Integrity Against Baseline");
            Console.WriteLine("--- Settings ---");
            Console.WriteLine(" 8. Select Working Directory");
            Console.WriteLine("--- Advanced Tools ---");
            Console.WriteLine(" 9. Packet Sniffer");
                        Console.WriteLine("10. WiFi Honeypot");
            Console.WriteLine("11. Advanced Network Reconnaissance (Nmap)");
            Console.WriteLine("-----------------------------");
            Console.WriteLine(" 0. Exit");
            Console.WriteLine("=============================");
            Console.Write("Enter your choice: ");
        }

        // Helper methods for colored console output
        static void PrintError(string message)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"ERROR: {message}");
            Console.ResetColor();
        }
        
        static void PrintWarning(string message)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"WARNING: {message}");
            Console.ResetColor();
        }
    }
}