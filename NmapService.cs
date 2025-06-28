using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using System.Xml.Linq;
using CyberUtils;

namespace Encryption_malware
{
    public class NmapService
    {
        private readonly string _nmapPath;

        public NmapService(NmapSettings settings)
        {
            if (settings == null || string.IsNullOrWhiteSpace(settings.NmapPath))
            {
                throw new ArgumentException("Nmap path setting is missing or empty.", nameof(settings));
            }
            _nmapPath = settings.NmapPath;
        }

        public async Task<NmapScanResult> RunScanAsync(string target, string arguments = "-sV -T4")
        {
            var processStartInfo = new ProcessStartInfo
            {
                FileName = _nmapPath,
                Arguments = $"{arguments} -oX - {target}",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

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
