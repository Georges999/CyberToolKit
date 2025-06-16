using PacketDotNet;
using SharpPcap;
using System;
using System.Text;
using System.Threading;
using System.Linq;
using ARSoft.Tools.Net.Dns;
using CyberToolKit; // Add this to access CapturedPacket

namespace CyberUtils
{
    public class PacketSnifferService
    {
        private ICaptureDevice? _device;
        private CancellationTokenSource? _cancellationTokenSource;

        public event Action<CapturedPacket>? PacketCaptured;

        public void Start(ICaptureDevice device, CancellationToken token)
        {
            _device = device;
            _device.OnPacketArrival += OnPacketArrival;
            _device.Open(DeviceModes.Promiscuous, 1000);
            _device.StartCapture();

            token.Register(() => Stop());
        }

        public void Stop()
        {
            if (_device != null)
            {
                if (_device.Started)
                {
                    try
                    {
                        _device.StopCapture();
                    }
                    catch { /* Ignore exceptions on stop */ }
                }
                _device.OnPacketArrival -= OnPacketArrival;
                try
                {
                    _device.Close();
                }
                catch { /* Ignore exceptions on close */ }
                _device = null;
            }
        }

        private void OnPacketArrival(object sender, PacketCapture e)
        {
            try
            {
                var rawPacket = e.GetPacket();
                var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

                var ipPacket = packet.Extract<IPPacket>();
                if (ipPacket == null) return;

                var tcpPacket = packet.Extract<TcpPacket>();
                var udpPacket = packet.Extract<UdpPacket>();

                string protocol;
                string info = "";

                if (tcpPacket != null)
                {
                    protocol = "TCP";
                    if (tcpPacket.PayloadData != null && tcpPacket.PayloadData.Length > 0)
                    {
                        info = ParseHttp(tcpPacket);
                    }
                }
                else if (udpPacket != null)
                {
                    protocol = "UDP";
                    if (udpPacket.DestinationPort == 53 || udpPacket.SourcePort == 53)
                    {
                        info = ParseDns(udpPacket);
                    }
                }
                else
                {
                    protocol = ipPacket.Protocol.ToString().ToUpperInvariant();
                }

                var capturedPacket = new CapturedPacket
                {
                    Timestamp = rawPacket.Timeval.Date,
                    SourceIp = ipPacket.SourceAddress.ToString(),
                    DestinationIp = ipPacket.DestinationAddress.ToString(),
                    Protocol = protocol,
                    Length = rawPacket.Data.Length,
                    Info = info
                };

                PacketCaptured?.Invoke(capturedPacket);
            }
            catch
            {
                // Ignore packet parsing errors
            }
        }

        private string ParseHttp(TcpPacket tcpPacket)
        {
            try
            {
                var payload = Encoding.UTF8.GetString(tcpPacket.PayloadData);
                if (payload.StartsWith("HTTP"))
                {
                    var firstLine = payload.Substring(0, payload.IndexOf('\n')).Trim();
                    return $"HTTP Response: {firstLine}";
                }
                else if (payload.Contains("HTTP/1"))
                {
                    var lines = payload.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    var requestLine = lines[0];
                    var hostLine = lines.FirstOrDefault(l => l.StartsWith("Host:", StringComparison.OrdinalIgnoreCase));
                    var host = hostLine?.Split(':')[1].Trim() ?? "";
                    return $"HTTP Request: {requestLine} ({host})";
                }
            }
            catch { /* Ignore parsing errors */ }
            return "";
        }

        private string ParseDns(UdpPacket udpPacket)
        {
            try
            {
                var dnsMessage = DnsMessage.Parse(udpPacket.PayloadData);
                if (dnsMessage.IsQuery)
                {
                    if (dnsMessage.Questions.Count > 0)
                    {
                        var question = dnsMessage.Questions[0];
                        return $"DNS Query: {question.Name} ({question.RecordType})";
                    }
                }
                else // It's a response
                {
                    if (dnsMessage.AnswerRecords.Count > 0)
                    {
                        var answer = dnsMessage.AnswerRecords.FirstOrDefault(a => a is ARecord);
                        if (answer is ARecord aRecord)
                        {
                            return $"DNS Response: {aRecord.Name} -> {aRecord.Address}";
                        }
                        // Fallback for other record types
                        var firstAnswer = dnsMessage.AnswerRecords[0];
                        return $"DNS Response: {firstAnswer.Name} ({firstAnswer.RecordType})";
                    }
                }
            }
            catch { /* Ignore parsing errors */ }
            return "";
        }
    }
}