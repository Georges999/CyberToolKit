using System;
using System.Collections.Concurrent;
using System.Linq;
using PacketDotNet;
using SharpPcap;

namespace CyberUtils
{
    public class PacketSnifferService
    {
        private readonly string _ifaceName;
        private readonly int _durationMs;

        public PacketSnifferService(string ifaceName, int durationMs)
        {
            _ifaceName = ifaceName;
            _durationMs = durationMs;
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
        dev.OnPacketArrival += (s, e) =>
        {
            var rawPacket = e.GetPacket();
            var pkt = PacketDotNet.Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
            var ip = pkt.Extract<IPv4Packet>()?.SourceAddress.ToString() ?? "Unknown";
            counts.AddOrUpdate(ip, 1, (_, c) => c + 1);
        };

        dev.Open(DeviceModes.Promiscuous, 1000);
        Console.WriteLine($"Sniffing on {dev.Description} for {_durationMs}ms...");
        dev.StartCapture();
        System.Threading.Thread.Sleep(_durationMs);
        dev.StopCapture();
        dev.Close();

        Console.WriteLine("Top talkers:");
        foreach (var kv in counts.OrderByDescending(kv => kv.Value).Take(5))
            Console.WriteLine($" {kv.Key}: {kv.Value} packets");
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
    }
}
