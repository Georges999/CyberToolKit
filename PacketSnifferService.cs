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
            var dev = CaptureDeviceList.Instance
                        .FirstOrDefault(d => d.Name.Contains(_ifaceName) || d.Description.Contains(_ifaceName));
            if (dev == null) { Console.WriteLine($"Interface '{_ifaceName}' not found."); return; }

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
            dev.Capture();
            System.Threading.Thread.Sleep(_durationMs);
            dev.Close();

            Console.WriteLine("Top talkers:");
            foreach (var kv in counts.OrderByDescending(kv => kv.Value).Take(5))
                Console.WriteLine($" {kv.Key}: {kv.Value} packets");
        }
    }
}
