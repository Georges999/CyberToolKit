using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace CyberUtils
{
    public class HoneypotService
    {
        private readonly HoneypotSettings _settings;
        private TcpListener? _listener; // Nullable
        private CancellationTokenSource? _cts; // Nullable

        public bool IsRunning { get; private set; } = false;

        public HoneypotService(HoneypotSettings settings)
        {
            _settings = settings ?? throw new ArgumentNullException(nameof(settings));
        }

        public async Task StartAsync()
        {
            if (IsRunning)
            {
                Log("Honeypot is already running.");
                return;
            }

            _cts = new CancellationTokenSource();
            CancellationToken token = _cts.Token;

            try
            {
                _listener = new TcpListener(IPAddress.Any, _settings.ListenPort);
                _listener.Start();
                IsRunning = true;
                Log($"Honeypot started. Listening on port {_settings.ListenPort}...");

                // Run the accept loop in a separate task
                await Task.Run(async () => await AcceptClientsAsync(token), token);

            }
            catch (SocketException ex)
            {
                Log($"Error starting honeypot: {ex.Message}. (Port already in use?)");
                IsRunning = false;
            }
            catch (Exception ex)
            {
                Log($"Unexpected error starting honeypot: {ex.Message}");
                 IsRunning = false;
            }
            finally
             {
                 if (!IsRunning && _listener != null)
                {
                     _listener.Stop(); // Ensure listener is stopped if start failed
                 }
            }
        }

        private async Task AcceptClientsAsync(CancellationToken token)
        {
             if (_listener == null) return; // Safety check

            try
            {
                while (!token.IsCancellationRequested)
                {
                    if (_listener.Pending()) // Check if a connection is waiting
                    {
                         TcpClient client = await _listener.AcceptTcpClientAsync(token); // Accept connection
                         // Handle client connection asynchronously without waiting for it to finish
                         _ = HandleClientAsync(client, token); // Fire-and-forget pattern for handling
                    }
                    else
                    {
                        // Avoid tight loop when no connections pending
                        await Task.Delay(100, token); // Wait 100ms before checking again
                    }
                }
            }
             catch (OperationCanceledException)
             {
                 Log("Honeypot stopping as requested.");
             }
             catch (Exception ex) when (ex is SocketException || ex is ObjectDisposedException) // Listener was stopped likely
             {
                Log("Honeypot listener stopped.");
             }
            catch (Exception ex)
            {
                Log($"Error in accept loop: {ex.Message}");
                // Consider stopping the honeypot completely here if needed
            }
             finally
            {
                 Log("Accept loop finished.");
                 IsRunning = false;
                _listener?.Stop(); // Ensure listener is stopped on exit
             }
        }

       private async Task HandleClientAsync(TcpClient client, CancellationToken token)
        {
            string clientIp = client.Client.RemoteEndPoint?.ToString() ?? "Unknown IP";
             Log($"Connection received from: {clientIp}");

            try
            {
                 using (client) // Ensure client resources are disposed
                 using (NetworkStream stream = client.GetStream())
                {
                    // Optionally send a fake banner
                     byte[] banner = Encoding.ASCII.GetBytes($"220 FakeService Ready. Logged connection from {clientIp}\r\n");
                     await stream.WriteAsync(banner, 0, banner.Length, token);
                    await stream.FlushAsync(token);


                    // Simple: Log connection and maybe read first few bytes sent, then close.
                    // Don't engage in complex protocol simulation unless needed and safe.
                    byte[] buffer = new byte[1024];
                     int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, token);
                     if (bytesRead > 0)
                     {
                        string receivedData = Encoding.ASCII.GetString(buffer, 0, bytesRead).Trim();
                         Log($"Received initial data from {clientIp}: {receivedData}");
                     }

                    // Gently close the connection from server-side
                    await Task.Delay(500, token); // Short delay
                    client.Close();
                     Log($"Closed connection from: {clientIp}");
                 }
            }
            catch (OperationCanceledException)
             {
                 // Expected when stopping
                 Log($"Handling for {clientIp} cancelled.");
             }
             catch (IOException ex) when (ex.InnerException is SocketException se &&
                                         (se.SocketErrorCode == SocketError.ConnectionReset ||
                                         se.SocketErrorCode == SocketError.ConnectionAborted))
             {
                // Client disconnected abruptly
                Log($"Client {clientIp} disconnected abruptly.");
             }
             catch (IOException ex)
            {
                 Log($"IO Error handling client {clientIp}: {ex.Message}");
             }
             catch (Exception ex)
            {
                 Log($"Error handling client {clientIp}: {ex.Message}");
            }
             finally
            {
                 if (client?.Connected ?? false) // Defensive check
                {
                    client.Close();
                 }
             }
        }


        public void Stop()
        {
            if (!IsRunning || _cts == null || _listener == null)
            {
                Log("Honeypot is not running or already stopped.");
                return;
            }

            Log("Stopping honeypot...");
            _cts.Cancel(); // Signal cancellation to the tasks
            _listener.Stop(); // Stop listening for new connections
             IsRunning = false; // Set flag immediately

             // Give tasks a moment to finish gracefully - adjust timeout as needed
            // Task.WhenAll(...) could be used if we kept track of client handler tasks
            Task.Delay(1000).Wait(); // Simple wait

            _cts.Dispose();
            _cts = null;
            _listener = null; // Allow GC
            Log("Honeypot stopped.");
        }

        private void Log(string message)
        {
            string logMessage = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {message}";
            Console.WriteLine($"[Honeypot] {logMessage}"); // Also log to console
            try
            {
                // Append to log file
                File.AppendAllText(_settings.LogFilePath, logMessage + Environment.NewLine);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Honeypot] Failed to write to log file {_settings.LogFilePath}: {ex.Message}");
            }
        }
    }
}