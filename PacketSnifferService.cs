using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.IO;
using PacketDotNet;
using PacketDotNet.Tcp;
using SharpPcap;

namespace CyberUtils
{
    public class PacketSnifferService
    {
        private readonly string _ifaceName;
        private readonly int _durationMs;
        private readonly string _captureFilePath;
        private readonly bool _saveToFile;
        private readonly List<WebsiteVisit> _websiteVisits = new List<WebsiteVisit>();
        private readonly ConcurrentDictionary<string, string> _dnsCache = new ConcurrentDictionary<string, string>();
        
        public PacketSnifferService(string ifaceName, int durationMs, string captureFilePath = null)
        {
            _ifaceName = ifaceName;
            _durationMs = durationMs;
            _captureFilePath = captureFilePath;
            _saveToFile = !string.IsNullOrEmpty(captureFilePath);
        }
        
        public void Run()
        {
            try
            {
                Console.WriteLine("Attempting to access network interfaces...");
                
                var devices = CaptureDeviceList.Instance;
                if (devices.Count == 0)
                {
                    Console.WriteLine("No capture devices found. Please install Npcap from https://npcap.com/");
                    return;
                }
                
                var dev = devices.FirstOrDefault(d => d.Name.Contains(_ifaceName) || d.Description.Contains(_ifaceName));
                if (dev == null)
                { 
                    Console.WriteLine($"Interface '{_ifaceName}' not found.");
                    Console.WriteLine("Available interfaces:");
                    foreach (var device in devices)
                    {
                        Console.WriteLine($" - {device.Description}");
                    }
                    return;
                }

                var counts = new ConcurrentDictionary<string, int>();
                var httpTraffic = new ConcurrentBag<HttpTraffic>();
                
        SharpPcap.LibPcap.CaptureFileWriterDevice? captureFile = null;
                
if (_saveToFile)
{
    try
    {
        // First open the device (required before creating capture file writer)
        dev.Open(DeviceModes.Promiscuous);
        
        // Now create the capture file writer with the correct parameters
        captureFile = new SharpPcap.LibPcap.CaptureFileWriterDevice(_captureFilePath);
        Console.WriteLine($"Saving packets to {_captureFilePath}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Error creating capture file: {ex.Message}");
        captureFile = null;
    }
}
                dev.OnPacketArrival += (s, e) =>
                {
                    var rawPacket = e.GetPacket();
                    
                    // Save packet to file if requested
                    if (_saveToFile && captureFile != null)
                    {
                        captureFile.Write(rawPacket);
                    }
                    
                    var pkt = PacketDotNet.Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
                    
                    // Extract basic IP info
                    var ipPacket = pkt.Extract<IPv4Packet>();
                    if (ipPacket != null)
                    {
                        string srcIp = ipPacket.SourceAddress.ToString();
                        counts.AddOrUpdate(srcIp, 1, (_, c) => c + 1);
                        
                        // Process TCP traffic (HTTP, HTTPS, etc)
                        var tcpPacket = ipPacket.Extract<TcpPacket>();
                        if (tcpPacket != null)
                        {
                            ProcessTcpPacket(tcpPacket, ipPacket, httpTraffic);
                        }
                        
                        // Process UDP traffic (mostly DNS)
                        var udpPacket = ipPacket.Extract<UdpPacket>();
                        if (udpPacket != null)
                        {
                            ProcessUdpPacket(udpPacket, ipPacket);
                        }
                    }
                };

                dev.Open(DeviceModes.Promiscuous, 1000);
                Console.WriteLine($"Sniffing on {dev.Description} for {_durationMs}ms...");
                Console.WriteLine("(Capturing web traffic and sensitive content...)");
                
                // Start the capture
                dev.StartCapture();
                
                // Show a progress bar
                int secondsTotal = _durationMs / 1000;
                for (int i = 0; i < secondsTotal; i++)
                {
                    Console.Write($"\rCapture progress: {i+1}/{secondsTotal} seconds");
                    System.Threading.Thread.Sleep(1000);
                }
                
                // Close everything properly
                dev.StopCapture();
                dev.Close();
                captureFile?.Close();

                // Display captured information
                DisplayResults(counts, httpTraffic);
            }
            catch (DllNotFoundException)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("ERROR: Missing packet capture drivers (wpcap.dll)");
                Console.WriteLine("Please install Npcap from: https://npcap.com/");
                Console.ResetColor();
                Console.WriteLine("Npcap is required for packet capture functionality.");
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"ERROR: {ex.GetType().Name} - {ex.Message}");
                Console.ResetColor();
            }
        }

        private void ProcessTcpPacket(TcpPacket tcpPacket, IPv4Packet ipPacket, ConcurrentBag<HttpTraffic> httpTraffic)
        {
            // HTTP (port 80) or HTTPS (port 443) traffic
            if (tcpPacket.DestinationPort == 80 || tcpPacket.SourcePort == 80 ||
                tcpPacket.DestinationPort == 443 || tcpPacket.SourcePort == 443)
            {
                string srcIp = ipPacket.SourceAddress.ToString();
                string dstIp = ipPacket.DestinationAddress.ToString();
                
                // Get hostnames from DNS cache if available
                string srcHost = _dnsCache.TryGetValue(srcIp, out var sh) ? sh : srcIp;
                string dstHost = _dnsCache.TryGetValue(dstIp, out var dh) ? dh : dstIp;
                
                // For outgoing connections
                if (tcpPacket.DestinationPort == 80 || tcpPacket.DestinationPort == 443)
                {
                    string protocol = tcpPacket.DestinationPort == 443 ? "HTTPS" : "HTTP";
                    
                    // Try to get HTTP data for non-HTTPS
                    if (protocol == "HTTP" && tcpPacket.PayloadData != null && tcpPacket.PayloadData.Length > 0)
                    {
                        string httpData = Encoding.ASCII.GetString(tcpPacket.PayloadData);
                        
                        // Look for HTTP requests
                        if (httpData.StartsWith("GET ") || httpData.StartsWith("POST ") || 
                            httpData.StartsWith("PUT ") || httpData.StartsWith("DELETE "))
                        {
                            // Extract HTTP method, URL, and host
                            var requestMatch = Regex.Match(httpData, @"^(\w+) (.*?) HTTP");
                            var hostMatch = Regex.Match(httpData, @"Host: (.*?)\r\n");
                            
                            if (requestMatch.Success && hostMatch.Success)
                            {
                                string method = requestMatch.Groups[1].Value;
                                string path = requestMatch.Groups[2].Value;
                                string host = hostMatch.Groups[1].Value.Trim();
                                
                                var traffic = new HttpTraffic
                                {
                                    Timestamp = DateTime.Now,
                                    Protocol = protocol,
                                    Method = method,
                                    Host = host,
                                    Path = path,
                                    SourceIp = srcIp,
                                    DestinationIp = dstIp
                                };
                                
                                // Look for sensitive data in POST requests (like passwords)
                                if (method == "POST" && httpData.Contains("Content-Type: application/x-www-form-urlencoded"))
                                {
                                    // Very simplistic - just looking for common patterns in form data
                                    var bodyMatch = Regex.Match(httpData, @"\r\n\r\n(.*?)$", RegexOptions.Singleline);
                                    if (bodyMatch.Success)
                                    {
                                        string body = bodyMatch.Groups[1].Value.Trim();
                                        traffic.RequestBody = body;
                                        
                                        // Look for password fields or other sensitive info
                                        if (body.Contains("password=") || body.Contains("pass=") || 
                                            body.Contains("user=") || body.Contains("username=") ||
                                            body.Contains("login=") || body.Contains("email="))
                                        {
                                            traffic.ContainsSensitiveData = true;
                                        }
                                    }
                                }
                                
                                httpTraffic.Add(traffic);
                                
                                // Record website visit
                                lock (_websiteVisits)
                                {
                                    _websiteVisits.Add(new WebsiteVisit
                                    {
                                        Timestamp = DateTime.Now,
                                        Host = host,
                                        Path = path,
                                        Protocol = protocol
                                    });
                                }
                            }
                        }
                    }
                    else if (protocol == "HTTPS")
                    {
                        // We can only see that an HTTPS connection was made, not the content
                        // Look for TLS Client Hello to detect initial connection
                        if (tcpPacket.PayloadData != null && tcpPacket.PayloadData.Length > 0 &&
                            tcpPacket.PayloadData[0] == 0x16) // TLS Handshake
                        {
                            // This is likely a new TLS connection - record the site being visited
                            // We can't see the hostname from TLS directly (SNI is encrypted)
                            // but we can use the destination IP and any DNS lookups we've seen
                            
                            var traffic = new HttpTraffic
                            {
                                Timestamp = DateTime.Now,
                                Protocol = protocol,
                                Host = dstHost,
                                SourceIp = srcIp,
                                DestinationIp = dstIp,
                                IsEncrypted = true
                            };
                            
                            httpTraffic.Add(traffic);
                        }
                    }
                }
            }
        }
        
        private void ProcessUdpPacket(UdpPacket udpPacket, IPv4Packet ipPacket)
        {
            // Look for DNS queries (port 53)
            if (udpPacket.DestinationPort == 53)
            {
                // Very simplified DNS packet parsing - just looking for domain names
                // Real DNS parsing requires much more detailed handling
                if (udpPacket.PayloadData != null && udpPacket.PayloadData.Length > 12) // DNS header is 12 bytes
                {
                    try
                    {
                        // Skip DNS header (12 bytes)
                        int offset = 12;
                        
                        // Parse question section (very simplified)
                        StringBuilder domainName = new StringBuilder();
                        
                        // Get the domain name from the question section
                        while (offset < udpPacket.PayloadData.Length)
                        {
                            int len = udpPacket.PayloadData[offset++];
                            if (len == 0) break; // End of domain name
                            
                            if (domainName.Length > 0) domainName.Append('.');
                            
                            // Get the label
                            for (int i = 0; i < len && offset < udpPacket.PayloadData.Length; i++)
                            {
                                domainName.Append((char)udpPacket.PayloadData[offset++]);
                            }
                        }
                        
                        if (domainName.Length > 0)
                        {
                            string domain = domainName.ToString();
                            string destIp = ipPacket.DestinationAddress.ToString();
                            
                            // Store in DNS cache for hostname resolution
                            _dnsCache[destIp] = domain;
                            
                            // Record the DNS lookup
                            lock (_websiteVisits)
                            {
                                _websiteVisits.Add(new WebsiteVisit
                                {
                                    Timestamp = DateTime.Now,
                                    Host = domain,
                                    Path = "",
                                    Protocol = "DNS Lookup"
                                });
                            }
                        }
                    }
                    catch
                    {
                        // Ignore DNS parsing errors
                    }
                }
            }
        }
        
        private void DisplayResults(ConcurrentDictionary<string, int> counts, ConcurrentBag<HttpTraffic> httpTraffic)
        {
            Console.WriteLine("\n\n==== Packet Capture Complete ====\n");
            
            Console.WriteLine("=== Top Talkers ===");
            foreach (var kv in counts.OrderByDescending(kv => kv.Value).Take(5))
                Console.WriteLine($" {kv.Key}: {kv.Value} packets");
            
            Console.WriteLine("\n=== Websites Visited ===");
            var groupedVisits = _websiteVisits
                .GroupBy(v => v.Host)
                .OrderByDescending(g => g.Count());
                
            foreach (var group in groupedVisits)
            {
                Console.WriteLine($" {group.Key} ({group.Count()} hits)");
                
                // Show up to 3 example paths for each host
                foreach (var visit in group.Take(3))
                {
                    if (!string.IsNullOrEmpty(visit.Path))
                        Console.WriteLine($"   - {visit.Protocol}: {visit.Path}");
                }
                
                if (group.Count() > 3)
                    Console.WriteLine($"   - ... and {group.Count() - 3} more");
            }
            
            // Show sensitive data if found
            var sensitiveTraffic = httpTraffic.Where(t => t.ContainsSensitiveData).ToList();
            if (sensitiveTraffic.Any())
            {
                Console.WriteLine("\n=== Potential Sensitive Data Detected ===");
                foreach (var traffic in sensitiveTraffic)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($" [!] {traffic.Method} {traffic.Host}{traffic.Path}");
                    Console.WriteLine($"     Form data: {traffic.RequestBody}");
                    Console.ResetColor();
                }
                Console.WriteLine("\nWARNING: Displaying unencrypted sensitive data is for educational purposes only.");
            }

            // Traffic volume summary
            Console.WriteLine("\n=== Traffic Summary ===");
            Console.WriteLine($"Total unique IPs detected: {counts.Count}");
            Console.WriteLine($"Total packets captured: {counts.Values.Sum()}");
            Console.WriteLine($"Total HTTP/HTTPS requests: {httpTraffic.Count}");
            Console.WriteLine($"Total websites visited: {groupedVisits.Count()}");
        }

public void RunWifiMonitor(bool captureAllDevices)
{
    try
    {
        Console.WriteLine("Starting WiFi monitoring mode...");
        
        var devices = CaptureDeviceList.Instance;
        if (devices.Count == 0)
        {
            Console.WriteLine("No capture devices found. Please install Npcap from https://npcap.com/");
            return;
        }
        
        // List all available interfaces for selection
        Console.WriteLine("\nAvailable wireless interfaces:");
        var wifiDevices = devices
            .Where(d => d.Description.ToLower().Contains("wi-fi") || 
                        d.Description.ToLower().Contains("wireless") ||
                        d.Description.ToLower().Contains("wlan"))
            .ToList();
            
        if (wifiDevices.Count == 0)
        {
            Console.WriteLine("No WiFi interfaces detected.");
            return;
        }
        
        for (int i = 0; i < wifiDevices.Count; i++)
        {
            Console.WriteLine($"{i+1}. {wifiDevices[i].Description}");
        }
        
        Console.Write("\nSelect WiFi interface: ");
        if (!int.TryParse(Console.ReadLine(), out int selection) || 
            selection < 1 || selection > wifiDevices.Count)
        {
            Console.WriteLine("Invalid selection");
            return;
        }
        
        var dev = wifiDevices[selection - 1];
        
        // Set up the monitoring
        var counts = new ConcurrentDictionary<string, int>();
        var deviceTraffic = new ConcurrentDictionary<string, DeviceTrafficInfo>();
        
        // Use promiscuous mode for capturing
        DeviceModes captureMode = DeviceModes.Promiscuous;
        try
        {
            dev.Open(captureMode, 1000);
            Console.WriteLine("Successfully opened adapter in advanced monitoring mode");
        }
        catch
        {
            // Fall back to regular promiscuous mode if monitor mode fails
            dev.Open(DeviceModes.Promiscuous, 1000);
            Console.WriteLine("Opened adapter in standard promiscuous mode");
            Console.WriteLine("Note: Some WiFi cards don't fully support monitoring all network traffic");
        }
        
        // Add packet handler to analyze all traffic
        dev.OnPacketArrival += (s, e) =>
        {
            var rawPacket = e.GetPacket();
            var pkt = PacketDotNet.Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
            
            // Try to get MAC addresses (useful for device identification)
            var ethernetPacket = pkt as EthernetPacket;
            if (ethernetPacket != null)
            {
                string srcMac = ethernetPacket.SourceHardwareAddress.ToString();
                string dstMac = ethernetPacket.DestinationHardwareAddress.ToString();
                
                // Track device by MAC address
                deviceTraffic.AddOrUpdate(srcMac, 
                    new DeviceTrafficInfo { 
                        MacAddress = srcMac, 
                        PacketsSent = 1 
                    },
                    (_, info) => {
                        info.PacketsSent++;
                        return info;
                    });
                
                deviceTraffic.AddOrUpdate(dstMac, 
                    new DeviceTrafficInfo { 
                        MacAddress = dstMac, 
                        PacketsReceived = 1 
                    },
                    (_, info) => {
                        info.PacketsReceived++;
                        return info;
                    });
            }
            
            // Extract IP info as before
            var ipPacket = pkt.Extract<IPv4Packet>();
            if (ipPacket != null)
            {
                string srcIp = ipPacket.SourceAddress.ToString();
                string dstIp = ipPacket.DestinationAddress.ToString();
                
                counts.AddOrUpdate(srcIp, 1, (_, c) => c + 1);
                
                // Map IP to MAC when possible
                if (ethernetPacket != null)
                {
                    string srcMac = ethernetPacket.SourceHardwareAddress.ToString();
                    
                    // Update device info with IP
                    deviceTraffic.AddOrUpdate(srcMac, 
                        new DeviceTrafficInfo { 
                            MacAddress = srcMac,
                            IpAddress = srcIp,
                            PacketsSent = 1 
                        },
                        (_, info) => {
                            info.IpAddress = srcIp;
                            return info;
                        });
                }
                
                // Process packets as before...
            }
        };
        
        Console.WriteLine($"Monitoring WiFi network on {dev.Description}...");
        Console.WriteLine("Press Ctrl+C to stop monitoring");
        
        dev.StartCapture();
        
        // Show progress and update stats periodically
        int monitorDuration = _durationMs;
        int updateInterval = 1000; // Update display every second
        int elapsedTime = 0;
        
        while (elapsedTime < monitorDuration)
        {
            Console.Clear();
            Console.WriteLine($"=== WiFi Network Monitor - {elapsedTime/1000}s elapsed ===\n");
            
            // Display current stats
            Console.WriteLine("Connected Devices:");
            foreach (var device in deviceTraffic.Values
                .Where(d => d.PacketsSent > 0 || d.PacketsReceived > 0)
                .OrderByDescending(d => d.PacketsSent + d.PacketsReceived)
                .Take(10))
            {
                Console.WriteLine($" {device.MacAddress} {(string.IsNullOrEmpty(device.IpAddress) ? "" : $"({device.IpAddress})")}");
                Console.WriteLine($"   Sent: {device.PacketsSent} packets, Received: {device.PacketsReceived} packets");
            }
            
            Console.WriteLine("\nPress Ctrl+C to stop monitoring");
            
            // Wait for update interval
            System.Threading.Thread.Sleep(updateInterval);
            elapsedTime += updateInterval;
        }
        
        // Stop capture
        dev.StopCapture();
        dev.Close();
        
        // Show final results
        DisplayNetworkResults(counts, deviceTraffic);
    }
    catch (DllNotFoundException)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("ERROR: Missing packet capture drivers (wpcap.dll)");
        Console.WriteLine("Please install Npcap from: https://npcap.com/");
        Console.ResetColor();
    }
    catch (Exception ex)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"ERROR: {ex.GetType().Name} - {ex.Message}");
        Console.ResetColor();
    }
}

// Add this helper method
private void DisplayNetworkResults(ConcurrentDictionary<string, int> counts, 
    ConcurrentDictionary<string, DeviceTrafficInfo> deviceTraffic)
{
    Console.Clear();
    Console.WriteLine("\n==== WiFi Monitoring Complete ====\n");
    
    Console.WriteLine("=== Detected Devices ===");
    foreach (var device in deviceTraffic.Values
        .Where(d => d.PacketsSent > 5 || d.PacketsReceived > 5) // Filter out noise
        .OrderByDescending(d => d.PacketsSent + d.PacketsReceived))
    {
        Console.WriteLine($"Device: {device.MacAddress}");
        if (!string.IsNullOrEmpty(device.IpAddress))
            Console.WriteLine($"  IP: {device.IpAddress}");
            
        Console.WriteLine($"  Traffic: {device.PacketsSent} packets sent, {device.PacketsReceived} packets received");
        Console.WriteLine($"  Vendor: {LookupVendorFromMac(device.MacAddress)}");
        Console.WriteLine();
    }
    
    Console.WriteLine("\n=== Network Statistics ===");
    Console.WriteLine($"Total unique devices detected: {deviceTraffic.Count(d => d.Value.PacketsSent > 5 || d.Value.PacketsReceived > 5)}");
    Console.WriteLine($"Total packets captured: {counts.Values.Sum()}");
    
    Console.WriteLine("\nNOTE: Due to WiFi encryption, packet contents between other devices cannot be decrypted");
    Console.WriteLine("Only packet metadata (sizes, timing, addressing) is visible for encrypted traffic.");
}

// Add a helper method to lookup MAC address vendors
private string LookupVendorFromMac(string macAddress)
{
    // This would ideally use a MAC vendor database
    // For now we'll just show some common ones
    if (string.IsNullOrEmpty(macAddress) || macAddress.Length < 8) return "Unknown";
    
    string oui = macAddress.Substring(0, 8).ToUpper();
    
    switch (oui)
    {
        case "00:0C:29": return "VMware";
        case "00:50:56": return "VMware";
        case "00:1A:11": return "Google";
        case "00:03:93": return "Apple";
        case "00:05:02": return "Apple"; 
        case "00:1C:B3": return "Apple";
        case "00:1E:52": return "Apple";
        case "00:1F:F3": return "Apple";
        case "00:21:E9": return "Apple";
        case "00:23:12": return "Apple";
        case "00:25:00": return "Apple";
        case "00:26:BB": return "Apple";
        case "28:CF:DA": return "Apple";
        case "3C:D9:2B": return "Hewlett Packard";
        case "9C:8E:99": return "Hewlett Packard";
        case "00:15:5D": return "Microsoft";
        case "00:50:F2": return "Microsoft";
        case "28:18:78": return "Microsoft";
        case "00:E0:4C": return "Realtek";
        case "00:14:22": return "Dell";
        case "14:18:77": return "Dell";
        case "00:19:B9": return "Dell";
        case "B8:AC:6F": return "Dell";
        default: return "Unknown";
    }
}

// Add this class to store device traffic information
public class DeviceTrafficInfo
{
    public string MacAddress { get; set; } = string.Empty;
    public string IpAddress { get; set; } = string.Empty; 
    public int PacketsSent { get; set; } = 0;
    public int PacketsReceived { get; set; } = 0;
    public List<string> Protocols { get; set; } = new List<string>();
}
    }

    
    
    // Helper classes
    public class WebsiteVisit
    {
        public DateTime Timestamp { get; set; }
        public string Host { get; set; }
        public string Path { get; set; }
        public string Protocol { get; set; }
    }
    
    public class HttpTraffic
    {
        public DateTime Timestamp { get; set; }
        public string Protocol { get; set; }
        public string Method { get; set; }
        public string Host { get; set; }
        public string Path { get; set; }
        public string SourceIp { get; set; }
        public string DestinationIp { get; set; }
        public string RequestBody { get; set; }
        public bool ContainsSensitiveData { get; set; }
        public bool IsEncrypted { get; set; }
    }
}