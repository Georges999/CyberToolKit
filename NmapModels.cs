using System.Collections.Generic;
using System.Text;

namespace Encryption_malware
{
    public class NmapScanResult
    {
        public List<Host> Hosts { get; set; } = new List<Host>();

        public override string ToString()
        {
            if (Hosts.Count == 0)
            {
                return "No hosts found or all hosts are down.";
            }

            var sb = new StringBuilder();
            foreach (var host in Hosts)
            {
                sb.AppendLine(host.ToString());
            }
            return sb.ToString();
        }
    }

    public class Host
    {
        public string IpAddress { get; set; }
        public string Hostname { get; set; }
        public string Status { get; set; }
        public List<Port> Ports { get; set; } = new List<Port>();

        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.AppendLine($"Host: {IpAddress} ({(string.IsNullOrEmpty(Hostname) ? "N/A" : Hostname)}) - Status: {Status}");
            if (Ports.Count > 0)
            {
                sb.AppendLine("  Open Ports:");
                foreach (var port in Ports)
                {
                    sb.AppendLine(port.ToString());
                }
            }
            else
            {
                sb.AppendLine("  No open ports found.");
            }
            return sb.ToString();
        }
    }

    public class Port
    {
        public int PortId { get; set; }
        public string Protocol { get; set; }
        public string State { get; set; }
        public Service Service { get; set; } = new Service();

        public override string ToString()
        {
            return $"    - Port {PortId}/{Protocol} ({State}): {Service}";
        }
    }

    public class Service
    {
        public string Name { get; set; }
        public string Product { get; set; }
        public string Version { get; set; }

        public override string ToString()
        {
            var parts = new List<string>();
            if (!string.IsNullOrEmpty(Name)) parts.Add($"Name: {Name}");
            if (!string.IsNullOrEmpty(Product)) parts.Add($"Product: {Product}");
            if (!string.IsNullOrEmpty(Version)) parts.Add($"Version: {Version}");
            return string.Join(", ", parts);
        }
    }
}
