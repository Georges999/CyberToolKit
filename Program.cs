using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration; // Required for ConfigurationBuilder

namespace CyberUtils
{
    class Program
    {
        private static AppSettings? _appSettings; // Nullable
        private static HoneypotService? _honeypotService; // Nullable
        private static Task? _honeypotTask; // Nullable task tracker
        private static string _currentDirectory = string.Empty;
        private static IConfigurationRoot? _configuration; // Store configuration

        static async Task Main(string[] args) // Main can be async now
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
                    .SetBasePath(Directory.GetCurrentDirectory()) // Expects json in executable directory
                    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true); // Make it non-optional

                _configuration = builder.Build();

                _appSettings = new AppSettings();
                _configuration.Bind(_appSettings); // Bind JSON structure to our AppSettings class

                // ** VERY IMPORTANT SECURITY WARNING **
                if (_appSettings?.FileOperations?.EncryptionKey == "!!REPLACE_THIS_WITH_A_STRONG_KEY!!")
                {
                    PrintWarning("SECURITY WARNING: Default encryption key found in appsettings.json! Replace it with a strong, unique key and protect the configuration file.");
                }
                Console.WriteLine("Configuration loaded.");
            }
            catch (FileNotFoundException)
            {
                PrintError("Error: appsettings.json not found in the application directory.");
                _appSettings = null; // Ensure settings are null if file missing
            }
            catch (Exception ex)
            {
                PrintError($"Error loading configuration: {ex.Message}");
                _appSettings = null; // Ensure settings are null on error
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
                        if (fileOps != null) {
                            // Use current directory
                            var settings = new FileOperationsSettings {
                                TargetDirectory = _currentDirectory,
                                EncryptionKey = _appSettings?.FileOperations?.EncryptionKey ?? string.Empty,
                                TempDirectory = _appSettings?.FileOperations?.TempDirectory ?? string.Empty
                            };
                            var tempService = new FileOperationsService(settings);
                            tempService.FindAndDisplayFiles();
                        }
                        else PrintError("File Operations module not initialized.");
                        break;
                    case "2": // Encrypt Files
                        if (fileOps != null) {
                            PrintWarning("This will encrypt files and is irreversible without the key. Type 'CONFIRM' to proceed:");
                            if (Console.ReadLine() == "CONFIRM") {
                                var settings = new FileOperationsSettings {
                                    TargetDirectory = _currentDirectory,
                                    EncryptionKey = _appSettings?.FileOperations?.EncryptionKey ?? string.Empty,
                                    TempDirectory = _appSettings?.FileOperations?.TempDirectory ?? string.Empty
                                };
                                var tempService = new FileOperationsService(settings);
                                tempService.EncryptFiles();
                            }
                            else Console.WriteLine("Encryption cancelled.");
                        } else PrintError("File Operations module not initialized.");
                        break;
                    case "3": // Decrypt Files
                        if (fileOps != null) {
                            PrintWarning("Attempting decryption. Ensure the correct key is in configuration.");
                            var settings = new FileOperationsSettings {
                                TargetDirectory = _currentDirectory,
                                EncryptionKey = _appSettings?.FileOperations?.EncryptionKey ?? string.Empty,
                                TempDirectory = _appSettings?.FileOperations?.TempDirectory ?? string.Empty
                            };
                            var tempService = new FileOperationsService(settings);
                            tempService.DecryptFiles();
                        } else PrintError("File Operations module not initialized.");
                        break;
                    case "4": // Start Honeypot
                        if (_honeypotService != null && !_honeypotService.IsRunning)
                        {
                            Console.WriteLine("Starting honeypot asynchronously...");
                            _honeypotTask = _honeypotService.StartAsync(); // Store task
                            // Don't await here, let it run in background
                        } else if (_honeypotService?.IsRunning ?? false) {
                            PrintWarning("Honeypot is already running.");
                        } else PrintError("Honeypot module not initialized.");
                        break;
                    case "5": // Stop Honeypot
                        if (_honeypotService?.IsRunning ?? false)
                        {
                            Console.WriteLine("Stopping honeypot...");
                            _honeypotService.Stop();
                            if (_honeypotTask != null && !_honeypotTask.IsCompleted)
                            {
                                Console.WriteLine("Waiting for honeypot task to stop...");
                                await _honeypotTask; // Wait for the task to actually finish
                                _honeypotTask = null; // Reset task tracker
                            }
                        } else PrintWarning("Honeypot is not running.");
                        break;
                    case "6": // Create Integrity Baseline
                        if (integrityChecker != null) {
                            // Use current directory for integrity checker
                            var settings = new IntegrityCheckerSettings {
                                BaselineFilePath = _appSettings?.IntegrityChecker?.BaselineFilePath ?? "file_integrity_baseline.json",
                                DirectoryToMonitor = _currentDirectory
                            };
                            var tempService = new IntegrityCheckerService(settings);
                            tempService.CreateBaseline();
                        }
                        else PrintError("Integrity Checker module not initialized.");
                        break;
                    case "7": // Verify Integrity
                        if (integrityChecker != null) {
                            // Use current directory for integrity checker
                            var settings = new IntegrityCheckerSettings {
                                BaselineFilePath = _appSettings?.IntegrityChecker?.BaselineFilePath ?? "file_integrity_baseline.json",
                                DirectoryToMonitor = _currentDirectory
                            };
                            var tempService = new IntegrityCheckerService(settings);
                            tempService.VerifyIntegrity();
                        }
                        else PrintError("Integrity Checker module not initialized.");
                        break;
                    case "8": // Select Working Directory
                        SelectWorkingDirectory();
                        break;
                    case "9": // Packet Sniffer
                        if (_configuration != null) {
                            var sec = _configuration.GetSection("PacketSniffer");
                            string iface = sec["InterfaceName"] ?? "Ethernet";
                            int duration = int.Parse(sec["CaptureDurationMs"] ?? "5000");
                            new PacketSnifferService(iface, duration).Run();
                        } else {
                            PrintError("Configuration not loaded properly");
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
                    Console.ReadLine(); // Pause before showing menu again
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