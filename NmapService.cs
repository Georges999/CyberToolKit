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
        CustomScan,
        // New advanced evasion scan types
        AntiForensicScan,
        FirewallEvasion,
        IdleZombieScan,
        FragmentationScan,
        DecoyNetworkScan,
        SlowComprehensiveScan,
        UDPScan,
        WindowsScan,
        UnixScan
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
                Console.Write("Select scan type (1-20, or 0 to exit): ");
                
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
            Console.WriteLine();
            Console.WriteLine("=== ADVANCED EVASION SCANS ===");
            Console.WriteLine("12. Anti-Forensic Scan (Maximum stealth)");
            Console.WriteLine("13. Firewall Evasion (Bypass firewalls)");
            Console.WriteLine("14. Idle Zombie Scan (Use zombie host)");
            Console.WriteLine("15. Fragmentation Scan (Fragment packets)");
            Console.WriteLine("16. Decoy Network Scan (Use decoy hosts)");
            Console.WriteLine("17. Slow Comprehensive (Avoid detection)");
            Console.WriteLine("18. UDP Scan (UDP services)");
            Console.WriteLine("19. Windows Target Scan (Windows-specific)");
            Console.WriteLine("20. Unix Target Scan (Unix/Linux-specific)");
            Console.WriteLine();
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
                // Advanced evasion scans
                case 12: scanType = ScanType.AntiForensicScan; break;
                case 13: scanType = ScanType.FirewallEvasion; break;
                case 14: 
                    scanType = ScanType.IdleZombieScan;
                    Console.Write("Enter zombie host IP (or press Enter for auto-detect): ");
                    string zombieHost = Console.ReadLine()?.Trim();
                    if (!string.IsNullOrEmpty(zombieHost))
                    {
                        // Replace zombie_host placeholder with actual IP
                        customArgs = $"-sI {zombieHost} -T2 -p 1-1000";
                    }
                    break;
                case 15: scanType = ScanType.FragmentationScan; break;
                case 16: scanType = ScanType.DecoyNetworkScan; break;
                case 17: scanType = ScanType.SlowComprehensiveScan; break;
                case 18: scanType = ScanType.UDPScan; break;
                case 19: scanType = ScanType.WindowsScan; break;
                case 20: scanType = ScanType.UnixScan; break;
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
                // Advanced evasion techniques
                ScanType.AntiForensicScan => "-sS -f -mtu 24 -T1 -D RND:10 --source-port 53 --spoof-mac 0",
                ScanType.FirewallEvasion => "-sA -f --mtu 24 -T2 --source-port 53 --data-length 25",
                ScanType.IdleZombieScan => !string.IsNullOrWhiteSpace(customArgs) ? customArgs : "-sI zombie_host -T2 -p 1-1000",
                ScanType.FragmentationScan => "-sS -f -ff -T2 --scan-delay 1s",
                ScanType.DecoyNetworkScan => "-sS -D RND:15 -T3 --randomize-hosts",
                ScanType.SlowComprehensiveScan => "-sS -sV -sC -T1 -p- --scan-delay 2s --max-parallelism 1",
                ScanType.UDPScan => "-sU -T4 --top-ports 1000",
                ScanType.WindowsScan => "-sS -O -sV -sC -p 135,139,445,3389,1433,5985,5986 --script smb-*,rdp-*,ms-sql-*",
                ScanType.UnixScan => "-sS -O -sV -sC -p 22,23,25,53,80,110,143,443,993,995 --script ssh-*,ftp-*,smtp-*",
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
                            var parts = ip.Split('.');
                            
                            if (parts.Length == 4 && int.TryParse(parts[0], out int firstOctet) && 
                                int.TryParse(parts[1], out int secondOctet))
                            {
                                // RFC 1918 private IP ranges with appropriate subnet assumptions
                                if (firstOctet == 10)
                                {
                                    // 10.0.0.0/8 - Class A private network
                                    return $"{parts[0]}.{parts[1]}.{parts[2]}.0/24";
                                }
                                else if (firstOctet == 172 && secondOctet >= 16 && secondOctet <= 31)
                                {
                                    // 172.16.0.0/12 - Class B private network (172.16.x.x to 172.31.x.x)
                                    return $"{parts[0]}.{parts[1]}.{parts[2]}.0/24";
                                }
                                else if (firstOctet == 192 && secondOctet == 168)
                                {
                                    // 192.168.0.0/16 - Class C private network
                                    return $"{parts[0]}.{parts[1]}.{parts[2]}.0/24";
                                }
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
                21 => "FTP - File Transfer Protocol (Try anonymous login, brute force)",
                22 => "SSH - Secure Shell (Try default credentials, brute force, check for weak keys)",
                23 => "Telnet - INSECURE remote administration (Easy to intercept credentials)",
                25 => "SMTP - Mail server (Check for open relay, user enumeration)",
                53 => "DNS - Domain name resolution (Try zone transfer, DNS enumeration)",
                80 => "HTTP - Web server (Check for admin panels, directory traversal, SQL injection)",
                110 => "POP3 - Email retrieval (Try brute force, check for clear text auth)",
                135 => "RPC - Windows RPC service (Potential for MS-RPC exploits)",
                139 => "NetBIOS - Windows file sharing (SMB enumeration, null sessions)",
                143 => "IMAP - Email server (Try brute force, check for clear text auth)",
                443 => "HTTPS - Secure web server (Check SSL/TLS config, web vulnerabilities)",
                445 => "SMB - Windows file sharing (Null sessions, SMB exploits, shares enumeration)",
                993 => "IMAPS - Secure email (Check SSL/TLS config)",
                995 => "POP3S - Secure email (Check SSL/TLS config)",
                1433 => "MSSQL - Microsoft SQL Server (Try sa account, SQL injection, xp_cmdshell)",
                1521 => "Oracle - Database server (Try default accounts, TNS enumeration)",
                3306 => "MySQL - Database server (Try root account, check for weak passwords)",
                3389 => "RDP - Remote Desktop Protocol (Try brute force, check for weak encryption)",
                5432 => "PostgreSQL - Database server (Try postgres account, check for weak passwords)",
                5900 => "VNC - Remote desktop access (Often no password or weak password)",
                5985 => "WinRM HTTP - Windows Remote Management (Try brute force, check for weak auth)",
                5986 => "WinRM HTTPS - Windows Remote Management (Check SSL/TLS config)",
                8080 => "HTTP-Alt - Alternative web server (Check for management interfaces)",
                8443 => "HTTPS-Alt - Alternative secure web server (Check SSL/TLS config)",
                27017 => "MongoDB - NoSQL database (Often no authentication, data exposure)",
                _ => null
            };

            if (!string.IsNullOrEmpty(analysis))
            {
                Console.WriteLine($"        Analysis: {analysis}");
                
                // Add specific attack suggestions based on service and version
                if (port.Service?.Product != null)
                {
                    string attackSuggestions = GetAttackSuggestions(port);
                    if (!string.IsNullOrEmpty(attackSuggestions))
                    {
                        Console.WriteLine($"        Attack Vectors: {attackSuggestions}");
                    }
                }
            }

            // Web server detection with more details
            if (IsWebPort(port.PortId))
            {
                string protocol = port.PortId == 443 || port.PortId == 8443 ? "https" : "http";
                Console.WriteLine($"        Web URL: {protocol}://{ipAddress}:{port.PortId}");
                Console.WriteLine($"        Recommended: Directory enumeration, vulnerability scanning");
            }
            
            // Database server detection
            if (IsDatabasePort(port.PortId))
            {
                Console.WriteLine($"        Database Target: {ipAddress}:{port.PortId}");
                Console.WriteLine($"        Recommended: Credential attacks, privilege escalation");
            }
        }

        private string GetAttackSuggestions(Port port)
        {
            var product = port.Service?.Product?.ToLower() ?? "";
            var version = port.Service?.Version?.ToLower() ?? "";
            
            // Check for known vulnerable versions
            if (product.Contains("openssh") && version.Contains("7.4"))
                return "OpenSSH 7.4 - Check for user enumeration vulnerability";
            if (product.Contains("apache") && version.Contains("2.2"))
                return "Apache 2.2 - Check for mod_ssl vulnerabilities";
            if (product.Contains("iis") && version.Contains("6.0"))
                return "IIS 6.0 - Check for WebDAV vulnerabilities";
            if (product.Contains("vsftpd") && version.Contains("2.3.4"))
                return "vsftpd 2.3.4 - BACKDOOR VULNERABILITY!";
            if (product.Contains("mysql") && version.Contains("5.0"))
                return "MySQL 5.0 - Check for privilege escalation";
            if (product.Contains("samba") && version.Contains("3.0"))
                return "Samba 3.0 - Check for username map script vulnerability";
                
            return "";
        }

        private bool IsDatabasePort(int port)
        {
            return port == 1433 || port == 3306 || port == 5432 || port == 1521 || port == 27017;
        }

        private bool IsWebPort(int port)
        {
            return port == 80 || port == 443 || port == 8080 || port == 8443 || port == 8000 || port == 8888 || 
                   port == 3000 || port == 4000 || port == 5000 || port == 9000 || port == 9090 || port == 9443;
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
