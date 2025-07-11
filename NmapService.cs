using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using System.Xml.Linq;
using CyberUtils;

namespace Encryption_malware
{
    public enum ScanType
    {
        HostDiscovery,
        QuickScan,
        FullPortScan,
        ServiceDetection,
        VulnerabilityAssessment,
        StealthScan,
        ComprehensiveScan,
        WebServerScan,
        DatabaseScan,
        CustomScan
    }

    public class NmapService
    {
        private readonly string _nmapPath;
        private readonly string _outputDirectory;

        public NmapService(NmapSettings settings)
        {
            if (settings == null || string.IsNullOrWhiteSpace(settings.NmapPath))
            {
                throw new ArgumentException("Nmap path setting is missing or empty.", nameof(settings));
            }
            _nmapPath = settings.NmapPath;
            _outputDirectory = Path.Combine(Directory.GetCurrentDirectory(), "nmap_results");
            if (!Directory.Exists(_outputDirectory))
            {
                Directory.CreateDirectory(_outputDirectory);
            }
        }

        public async Task RunInteractiveScanAsync()
        {
            Console.Clear();
            Console.WriteLine("=== NMAP NETWORK RECONNAISSANCE TOOL ===");
            Console.WriteLine("Advanced Network Discovery and Security Assessment");
            Console.WriteLine(new string('=', 50));

            // Auto-detect local network
            string localNetwork = GetLocalNetworkRange();
            Console.WriteLine($"Detected local network: {localNetwork}");
            Console.WriteLine();

            while (true)
            {
                DisplayScanMenu();
                Console.Write("Select scan type (1-11, or 0 to exit): ");
                
                if (!int.TryParse(Console.ReadLine(), out int choice))
                {
                    Console.WriteLine("Invalid input. Please enter a number.");
                    continue;
                }

                if (choice == 0) break;

                await ProcessScanChoice(choice, localNetwork);
                
                Console.WriteLine("\nPress Enter to continue...");
                Console.ReadLine();
            }
        }

        private void DisplayScanMenu()
        {
            Console.WriteLine("=== SCAN TYPES ===");
            Console.WriteLine(" 1. Host Discovery (Find live devices)");
            Console.WriteLine(" 2. Quick Scan (Top 100 ports)");
            Console.WriteLine(" 3. Full Port Scan (All 65535 ports)");
            Console.WriteLine(" 4. Service Detection (Identify services)");
            Console.WriteLine(" 5. Vulnerability Assessment (Security scan)");
            Console.WriteLine(" 6. Stealth Scan (Low detection)");
            Console.WriteLine(" 7. Comprehensive Scan (Everything)");
            Console.WriteLine(" 8. Web Server Focus (HTTP/HTTPS analysis)");
            Console.WriteLine(" 9. Database Discovery (Database services)");
            Console.WriteLine("10. Network Sweep (Entire subnet)");
            Console.WriteLine("11. Custom Scan (Enter your own options)");
            Console.WriteLine(" 0. Exit");
            Console.WriteLine();
        }

        private async Task ProcessScanChoice(int choice, string defaultTarget)
        {
            string target = defaultTarget;
            string customArgs = "";
            ScanType scanType;

            // Get target if needed
            if (choice != 10) // Network sweep uses default target
            {
                Console.Write($"Enter target (default: {defaultTarget}): ");
                string input = Console.ReadLine();
                if (!string.IsNullOrWhiteSpace(input))
                {
                    target = input.Trim();
                }
            }

            switch (choice)
            {
                case 1: scanType = ScanType.HostDiscovery; break;
                case 2: scanType = ScanType.QuickScan; break;
                case 3: scanType = ScanType.FullPortScan; break;
                case 4: scanType = ScanType.ServiceDetection; break;
                case 5: scanType = ScanType.VulnerabilityAssessment; break;
                case 6: scanType = ScanType.StealthScan; break;
                case 7: scanType = ScanType.ComprehensiveScan; break;
                case 8: scanType = ScanType.WebServerScan; break;
                case 9: scanType = ScanType.DatabaseScan; break;
                case 10: scanType = ScanType.HostDiscovery; target = defaultTarget; break;
                case 11: 
                    scanType = ScanType.CustomScan;
                    Console.Write("Enter custom Nmap arguments: ");
                    customArgs = Console.ReadLine() ?? "";
                    break;
                default:
                    Console.WriteLine("Invalid choice.");
                    return;
            }

            Console.WriteLine($"\nStarting {scanType} scan on {target}...");
            Console.WriteLine("This may take a while depending on the scan type.");
            Console.WriteLine();

            try
            {
                var result = await RunScanAsync(target, scanType, customArgs);
                DisplayResults(result, scanType);
                await SaveResults(result, scanType, target);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Scan failed: {ex.Message}");
            }
        }

        public async Task<NmapScanResult> RunScanAsync(string target, ScanType scanType = ScanType.QuickScan, string customArgs = "")
        {
            string arguments = GetScanArguments(scanType, customArgs);
            
            var processStartInfo = new ProcessStartInfo
            {
                FileName = _nmapPath,
                Arguments = $"{arguments} -oX - {target}",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            Console.WriteLine($"Executing: nmap {arguments} {target}");
            Console.WriteLine("Scanning in progress...");

            using (var process = new Process { StartInfo = processStartInfo })
            {
                try
                {
                    process.Start();
                }
                catch (Exception ex)
                {
                    throw new InvalidOperationException($"Failed to start Nmap. Ensure Nmap is installed and in your system's PATH, or specify the full path. Error: {ex.Message}");
                }

                string output = await process.StandardOutput.ReadToEndAsync();
                string error = await process.StandardError.ReadToEndAsync();
                await process.WaitForExitAsync();

                if (process.ExitCode != 0)
                {
                    throw new Exception($"Nmap scan failed with exit code {process.ExitCode}. Error: {error}");
                }

                if (string.IsNullOrWhiteSpace(output))
                {
                    throw new Exception("Nmap produced no output.");
                }

                return ParseNmapXml(output);
            }
        }

        private string GetScanArguments(ScanType scanType, string customArgs = "")
        {
            return scanType switch
            {
                ScanType.HostDiscovery => "-sn -T4",
                ScanType.QuickScan => "-sV -T4 --top-ports 100",
                ScanType.FullPortScan => "-sS -T4 -p-",
                ScanType.ServiceDetection => "-sV -sC -T4 -p 1-1000",
                ScanType.VulnerabilityAssessment => "-sV -sC --script vuln,safe -T3",
                ScanType.StealthScan => "-sS -f -T2 -D RND:10",
                ScanType.ComprehensiveScan => "-sS -sV -sC -A -T4 -p- --script=default,discovery,safe",
                ScanType.WebServerScan => "-sV -sC -p 80,443,8080,8443,8000,8888 --script http-*",
                ScanType.DatabaseScan => "-sV -sC -p 1433,3306,5432,1521,27017 --script *sql*,*mysql*,*oracle*",
                ScanType.CustomScan => !string.IsNullOrWhiteSpace(customArgs) ? customArgs : "-sV -T4",
                _ => "-sV -T4"
            };
        }

        private string GetLocalNetworkRange()
        {
            try
            {
                var networkInterfaces = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(ni => ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 || 
                                ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet)
                    .Where(ni => ni.OperationalStatus == OperationalStatus.Up);

                foreach (var networkInterface in networkInterfaces)
                {
                    var ipProperties = networkInterface.GetIPProperties();
                    foreach (var unicastAddress in ipProperties.UnicastAddresses)
                    {
                        if (unicastAddress.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
                            !IPAddress.IsLoopback(unicastAddress.Address))
                        {
                            var ip = unicastAddress.Address.ToString();
                            if (ip.StartsWith("192.168.") || ip.StartsWith("10.") || ip.StartsWith("172."))
                            {
                                var parts = ip.Split('.');
                                return $"{parts[0]}.{parts[1]}.{parts[2]}.0/24";
                            }
                        }
                    }
                }
            }
            catch
            {
                // Fall back to common network
            }
            
            return "192.168.1.0/24";
        }

        private void DisplayResults(NmapScanResult result, ScanType scanType)
        {
            Console.WriteLine();
            Console.WriteLine("=== SCAN RESULTS ===");
            Console.WriteLine(new string('=', 50));

            if (!result.Hosts.Any() || result.Hosts.All(h => h.Status != "up"))
            {
                Console.WriteLine("No live hosts found.");
                return;
            }

            foreach (var host in result.Hosts.Where(h => h.Status == "up"))
            {
                DisplayHostInformation(host, scanType);
                Console.WriteLine();
            }

            DisplayScanSummary(result, scanType);
        }

        private void DisplayHostInformation(Host host, ScanType scanType)
        {
            Console.WriteLine($"Host: {host.IpAddress}");
            
            if (!string.IsNullOrEmpty(host.Hostname))
            {
                Console.WriteLine($"Hostname: {host.Hostname}");
            }
            
            Console.WriteLine($"Status: {host.Status}");

            if (host.Ports.Any())
            {
                Console.WriteLine("Open Ports:");
                Console.WriteLine("Port\tProtocol\tService\t\tProduct/Version");
                Console.WriteLine(new string('-', 60));

                foreach (var port in host.Ports.Where(p => p.State == "open"))
                {
                    string service = port.Service?.Name ?? "unknown";
                    string product = port.Service?.Product ?? "";
                    string version = port.Service?.Version ?? "";
                    string productVersion = $"{product} {version}".Trim();
                    
                    Console.WriteLine($"{port.PortId}\t{port.Protocol}\t\t{service}\t\t{productVersion}");
                    
                    // Special analysis for common services
                    AnalyzeService(port, host.IpAddress);
                }
            }
            else if (scanType == ScanType.HostDiscovery)
            {
                Console.WriteLine("Host is alive (responding to ping)");
            }
        }

        private void AnalyzeService(Port port, string ipAddress)
        {
            string analysis = port.PortId switch
            {
                22 => "SSH server - Remote administration available",
                23 => "Telnet - INSECURE remote administration",
                25 => "SMTP - Mail server",
                53 => "DNS - Domain name resolution",
                80 => "HTTP - Web server (check for admin panels)",
                135 => "RPC - Windows RPC service",
                139 => "NetBIOS - Windows file sharing",
                143 => "IMAP - Email server",
                443 => "HTTPS - Secure web server",
                445 => "SMB - Windows file sharing",
                993 => "IMAPS - Secure email",
                995 => "POP3S - Secure email",
                1433 => "MSSQL - Microsoft SQL Server",
                3306 => "MySQL - Database server",
                3389 => "RDP - Remote Desktop Protocol",
                5432 => "PostgreSQL - Database server",
                5900 => "VNC - Remote desktop access",
                8080 => "HTTP-Alt - Alternative web server",
                8443 => "HTTPS-Alt - Alternative secure web server",
                _ => null
            };

            if (!string.IsNullOrEmpty(analysis))
            {
                Console.WriteLine($"        Analysis: {analysis}");
            }

            // Web server detection
            if (IsWebPort(port.PortId))
            {
                string protocol = port.PortId == 443 || port.PortId == 8443 ? "https" : "http";
                Console.WriteLine($"        Web URL: {protocol}://{ipAddress}:{port.PortId}");
            }
        }

        private bool IsWebPort(int port)
        {
            return port == 80 || port == 443 || port == 8080 || port == 8443 || port == 8000 || port == 8888;
        }

        private void DisplayScanSummary(NmapScanResult result, ScanType scanType)
        {
            Console.WriteLine("=== SUMMARY ===");
            int liveHosts = result.Hosts.Count(h => h.Status == "up");
            int totalPorts = result.Hosts.SelectMany(h => h.Ports).Count(p => p.State == "open");
            
            Console.WriteLine($"Live hosts found: {liveHosts}");
            Console.WriteLine($"Open ports found: {totalPorts}");
            
            // Identify interesting findings
            var webServers = result.Hosts.Where(h => h.Ports.Any(p => IsWebPort(p.PortId) && p.State == "open")).ToList();
            var sshServers = result.Hosts.Where(h => h.Ports.Any(p => p.PortId == 22 && p.State == "open")).ToList();
            var databases = result.Hosts.Where(h => h.Ports.Any(p => 
                (p.PortId == 1433 || p.PortId == 3306 || p.PortId == 5432) && p.State == "open")).ToList();

            if (webServers.Any())
                Console.WriteLine($"Web servers found: {webServers.Count}");
            if (sshServers.Any())
                Console.WriteLine($"SSH servers found: {sshServers.Count}");
            if (databases.Any())
                Console.WriteLine($"Database servers found: {databases.Count}");

            Console.WriteLine($"Scan completed at: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        }

        private async Task SaveResults(NmapScanResult result, ScanType scanType, string target)
        {
            try
            {
                string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                string filename = $"nmap_{scanType}_{target.Replace("/", "_").Replace(":", "_")}_{timestamp}";
                
                // Save as JSON for OWASP ZAP integration
                string jsonPath = Path.Combine(_outputDirectory, $"{filename}.json");
                await File.WriteAllTextAsync(jsonPath, System.Text.Json.JsonSerializer.Serialize(result, new System.Text.Json.JsonSerializerOptions 
                { 
                    WriteIndented = true 
                }));

                // Save as readable text report
                string txtPath = Path.Combine(_outputDirectory, $"{filename}.txt");
                await SaveTextReport(result, scanType, target, txtPath);

                Console.WriteLine($"Results saved to:");
                Console.WriteLine($"  JSON (for OWASP ZAP): {jsonPath}");
                Console.WriteLine($"  Text Report: {txtPath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to save results: {ex.Message}");
            }
        }

        private async Task SaveTextReport(NmapScanResult result, ScanType scanType, string target, string filePath)
        {
            using var writer = new StreamWriter(filePath);
            
            await writer.WriteLineAsync("=== NMAP SCAN REPORT ===");
            await writer.WriteLineAsync($"Scan Type: {scanType}");
            await writer.WriteLineAsync($"Target: {target}");
            await writer.WriteLineAsync($"Timestamp: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            await writer.WriteLineAsync(new string('=', 50));
            await writer.WriteLineAsync();

            foreach (var host in result.Hosts.Where(h => h.Status == "up"))
            {
                await writer.WriteLineAsync($"Host: {host.IpAddress}");
                if (!string.IsNullOrEmpty(host.Hostname))
                    await writer.WriteLineAsync($"Hostname: {host.Hostname}");
                await writer.WriteLineAsync($"Status: {host.Status}");
                await writer.WriteLineAsync();

                if (host.Ports.Any(p => p.State == "open"))
                {
                    await writer.WriteLineAsync("Open Ports:");
                    foreach (var port in host.Ports.Where(p => p.State == "open"))
                    {
                        await writer.WriteLineAsync($"  {port.PortId}/{port.Protocol} - {port.Service?.Name ?? "unknown"}");
                        if (!string.IsNullOrEmpty(port.Service?.Product))
                        {
                            await writer.WriteLineAsync($"    Product: {port.Service.Product} {port.Service.Version}".Trim());
                        }
                    }
                }
                await writer.WriteLineAsync();
            }
        }

        // Method for OWASP ZAP integration
        public async Task<List<string>> GetWebTargetsAsync(string network)
        {
            var result = await RunScanAsync(network, ScanType.WebServerScan);
            var webTargets = new List<string>();

            foreach (var host in result.Hosts.Where(h => h.Status == "up"))
            {
                foreach (var port in host.Ports.Where(p => IsWebPort(p.PortId) && p.State == "open"))
                {
                    string protocol = port.PortId == 443 || port.PortId == 8443 ? "https" : "http";
                    webTargets.Add($"{protocol}://{host.IpAddress}:{port.PortId}");
                }
            }

            return webTargets;
        }

        private NmapScanResult ParseNmapXml(string xmlOutput)
        {
            var result = new NmapScanResult();
            var doc = XDocument.Parse(xmlOutput);

            foreach (var hostElement in doc.Descendants("host"))
            {
                var host = new Host
                {
                    Status = hostElement.Element("status")?.Attribute("state")?.Value,
                    IpAddress = hostElement.Element("address")?.Attribute("addr")?.Value,
                    Hostname = hostElement.Element("hostnames")?.Element("hostname")?.Attribute("name")?.Value
                };

                var portsElement = hostElement.Element("ports");
                if (portsElement != null)
                {
                    foreach (var portElement in portsElement.Elements("port"))
                    {
                        var serviceElement = portElement.Element("service");
                        var port = new Port
                        {
                            PortId = int.Parse(portElement.Attribute("portid").Value),
                            Protocol = portElement.Attribute("protocol").Value,
                            State = portElement.Element("state")?.Attribute("state")?.Value,
                            Service = new Service
                            {
                                Name = serviceElement?.Attribute("name")?.Value,
                                Product = serviceElement?.Attribute("product")?.Value,
                                Version = serviceElement?.Attribute("version")?.Value
                            }
                        };
                        host.Ports.Add(port);
                    }
                }
                result.Hosts.Add(host);
            }

            return result;
        }
    }
}
