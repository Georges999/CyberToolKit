using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace CyberUtils
{
    public class HoneypotService
    {
        private readonly HoneypotSettings _settings;
        private TcpListener? _listener; // Nullable
        private CancellationTokenSource? _cts; // Nullable
        private readonly Dictionary<string, int> _attackerStats = new Dictionary<string, int>();
        private readonly object _statsLock = new object();

        public bool IsRunning { get; private set; } = false;

        public HoneypotService(HoneypotSettings settings)
        {
            _settings = settings ?? throw new ArgumentNullException(nameof(settings));
            
            // Create log directory if it doesn't exist
            string logDir = Path.GetDirectoryName(_settings.LogFilePath);
            if (!string.IsNullOrEmpty(logDir) && !Directory.Exists(logDir))
            {
                Directory.CreateDirectory(logDir);
            }
        }

        public async Task StartAsync()
        {
            if (IsRunning)
            {
                Log("Honeypot is already running.", LogLevel.Warning);
                return;
            }

            _cts = new CancellationTokenSource();
            CancellationToken token = _cts.Token;

            try
            {
                _listener = new TcpListener(IPAddress.Any, _settings.ListenPort);
                _listener.Start();
                IsRunning = true;
                Log($"Honeypot started. Listening on port {_settings.ListenPort}...", LogLevel.Info);

                // Run the accept loop in a separate task
                await Task.Run(async () => await AcceptClientsAsync(token), token);
            }
            catch (SocketException ex)
            {
                Log($"Error starting honeypot: {ex.Message}. (Port already in use?)", LogLevel.Error);
                IsRunning = false;
            }
            catch (Exception ex)
            {
                Log($"Unexpected error starting honeypot: {ex.Message}", LogLevel.Error);
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
                        
                        // Set reasonable timeout to prevent resource exhaustion
                        client.ReceiveTimeout = 30000; // 30 seconds
                        client.SendTimeout = 30000;
                        
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
                Log("Honeypot stopping as requested.", LogLevel.Info);
            }
            catch (Exception ex) when (ex is SocketException || ex is ObjectDisposedException) // Listener was stopped likely
            {
                Log("Honeypot listener stopped.", LogLevel.Info);
            }
            catch (Exception ex)
            {
                Log($"Error in accept loop: {ex.Message}", LogLevel.Error);
                // Consider stopping the honeypot completely here if needed
            }
            finally
            {
                Log("Accept loop finished.", LogLevel.Debug);
                IsRunning = false;
                _listener?.Stop(); // Ensure listener is stopped on exit
            }
        }

        private async Task HandleClientAsync(TcpClient client, CancellationToken token)
        {
            string clientIp = client.Client.RemoteEndPoint?.ToString() ?? "Unknown IP";
            string clientIpAddress = clientIp.Split(':')[0]; // Extract just the IP without port
            
            // Track connection count per IP
            lock (_statsLock)
            {
                if (_attackerStats.ContainsKey(clientIpAddress))
                    _attackerStats[clientIpAddress]++;
                else
                    _attackerStats[clientIpAddress] = 1;
            }
            
            Log($"Connection received from: {clientIp} (Count: {_attackerStats[clientIpAddress]})", LogLevel.Info);

            try
            {
                using (client) // Ensure client resources are disposed
                using (NetworkStream stream = client.GetStream())
                {
                    stream.ReadTimeout = 10000; // 10 seconds timeout for reads
                    
                    // Buffer to read client request
                    byte[] buffer = new byte[8192]; // Larger buffer for HTTP requests
                    int bytesRead;
                    
                    // Try to read the request
                    bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, token);
                    
                    if (bytesRead > 0)
                    {
                        string request = Encoding.ASCII.GetString(buffer, 0, bytesRead).Trim();
                        
                        // Log the request with detailed analysis
                        LogRequest(clientIp, request);
                        
                        // Determine if this is an HTTP request or something else
                        if (request.StartsWith("GET") || request.StartsWith("POST") || 
                            request.StartsWith("HEAD") || request.StartsWith("PUT"))
                        {
                            await HandleHttpRequestAsync(stream, request, clientIp, token);
                        }
                        else if (request.StartsWith("SSH-"))
                        {
                            // Handle SSH protocol attempt
                            await HandleSshAttemptAsync(stream, request, clientIp, token);
                        }
                        else if (request.Contains("USER") || request.Contains("PASS"))
                        {
                            // Likely FTP or similar protocol
                            await HandleFtpAttemptAsync(stream, request, clientIp, token);
                        }
                        else
                        {
                            // Unknown protocol, send generic response
                            await HandleUnknownProtocolAsync(stream, request, clientIp, token);
                        }
                    }
                }
            }
            catch (OperationCanceledException)
            {
                Log($"Handling for {clientIp} cancelled.", LogLevel.Debug);
            }
            catch (IOException ex) when (ex.InnerException is SocketException se &&
                                        (se.SocketErrorCode == SocketError.ConnectionReset ||
                                        se.SocketErrorCode == SocketError.ConnectionAborted))
            {
                // Client disconnected abruptly
                Log($"Client {clientIp} disconnected abruptly.", LogLevel.Warning);
            }
            catch (IOException ex)
            {
                Log($"IO Error handling client {clientIp}: {ex.Message}", LogLevel.Error);
            }
            catch (Exception ex)
            {
                Log($"Error handling client {clientIp}: {ex.Message}", LogLevel.Error);
            }
            finally
            {
                if (client?.Connected ?? false) // Defensive check
                {
                    client.Close();
                }
                Log($"Closed connection from: {clientIp}", LogLevel.Debug);
            }
        }

        private void LogRequest(string clientIp, string request)
        {
            // Extract and log significant details from the request
            try
            {
                StringBuilder analysis = new StringBuilder();
                analysis.AppendLine($"Request from {clientIp} at {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                analysis.AppendLine("-------- RAW REQUEST --------");
                analysis.AppendLine(request);
                analysis.AppendLine("----------------------------");
                
                // Extract HTTP method, URL, and version if present
                if (request.StartsWith("GET") || request.StartsWith("POST") || 
                    request.StartsWith("PUT") || request.StartsWith("DELETE"))
                {
                    string[] requestLines = request.Split('\n');
                    string[] requestParts = requestLines[0].Split(' ');
                    
                    if (requestParts.Length >= 3)
                    {
                        analysis.AppendLine($"Method: {requestParts[0]}");
                        analysis.AppendLine($"Path: {requestParts[1]}");
                        analysis.AppendLine($"Version: {requestParts[2]}");
                    }
                    
                    // Extract headers
                    analysis.AppendLine("Headers:");
                    bool inHeaders = true;
                    foreach (string line in requestLines.Skip(1))
                    {
                        if (string.IsNullOrWhiteSpace(line))
                        {
                            inHeaders = false;
                            analysis.AppendLine("Body:");
                            continue;
                        }
                        
                        if (inHeaders)
                        {
                            analysis.AppendLine($"  {line}");
                            
                            // Extract user agent
                            if (line.StartsWith("User-Agent:", StringComparison.OrdinalIgnoreCase))
                            {
                                analysis.AppendLine($"User-Agent: {line.Substring(11).Trim()}");
                            }
                            // Extract host
                            else if (line.StartsWith("Host:", StringComparison.OrdinalIgnoreCase))
                            {
                                analysis.AppendLine($"Host: {line.Substring(5).Trim()}");
                            }
                        }
                        else
                        {
                            // Body content
                            analysis.AppendLine(line);
                        }
                    }
                }
                
                // Look for potential exploits, SQL injection, etc.
                if (ContainsSuspiciousContent(request))
                {
                    analysis.AppendLine("!!! POTENTIAL ATTACK DETECTED !!!");
                    
                    if (request.Contains("' OR '1'='1"))
                        analysis.AppendLine("Detected: Basic SQL Injection attempt");
                    if (request.Contains("<script>"))
                        analysis.AppendLine("Detected: Potential XSS attempt");
                    if (request.Contains("../"))
                        analysis.AppendLine("Detected: Directory traversal attempt");
                    if (Regex.IsMatch(request, @"/bin/(?:bash|sh)"))
                        analysis.AppendLine("Detected: Shell command attempt");
                }
                
                // Log the detailed analysis
                Log(analysis.ToString(), LogLevel.Detail);
            }
            catch (Exception ex)
            {
                Log($"Error analyzing request: {ex.Message}", LogLevel.Error);
            }
        }

        private bool ContainsSuspiciousContent(string request)
        {
            // Check for common attack patterns
            string[] patterns = new string[] 
            {
                "'OR'", "' OR '", "1=1", "--", "/*", "*/", "DROP TABLE", "UNION SELECT",
                "<script>", "javascript:", "onload=", "onerror=", "onclick=",
                "../", "..\\", "/etc/passwd", "c:\\windows",
                "/bin/bash", "/bin/sh", "cmd.exe", "powershell",
                "nmap", "sqlmap", "nikto", "metasploit"
            };
            
            return patterns.Any(p => request.Contains(p, StringComparison.OrdinalIgnoreCase));
        }

        private async Task HandleHttpRequestAsync(NetworkStream stream, string request, string clientIp, CancellationToken token)
        {
            Log($"HTTP request received from {clientIp}", LogLevel.Info);
            
            // Parse the request to determine which page they're requesting
            string[] requestLines = request.Split('\n');
            string[] requestParts = requestLines[0].Split(' ');
            
            if (requestParts.Length < 2)
            {
                await SendHttpResponseAsync(stream, "400 Bad Request", "Invalid HTTP request", token);
                return;
            }
            
            string path = requestParts[1].ToLower();
            
            // Simulate a basic website
            if (path == "/" || path == "/index.html")
            {
                await SendHttpResponseAsync(stream, "200 OK", CreateFakeHomepage(), token);
            }
            else if (path == "/login" || path == "/login.php" || path == "/admin/login")
            {
                // Check if this was a POST with credentials
                if (request.Contains("username=") || request.Contains("password=") || request.Contains("user=") || request.Contains("pass="))
                {
                    // Extract credentials from the request
                    ExtractCredentials(request, clientIp);
                    
                    // Send "invalid credentials" page
                    await SendHttpResponseAsync(stream, "401 Unauthorized", CreateFakeLoginFailedPage(), token);
                }
                else
                {
                    // Send a fake login page
                    await SendHttpResponseAsync(stream, "200 OK", CreateFakeLoginPage(), token);
                }
            }
            else if (path.Contains("admin") || path.Contains("dashboard"))
            {
                await SendHttpResponseAsync(stream, "403 Forbidden", CreateFakeAdminForbiddenPage(), token);
            }
            else if (path.Contains("wp-") || path.Contains("wordpress"))
            {
                await SendHttpResponseAsync(stream, "200 OK", CreateFakeWordpressPage(), token);
            }
            else if (path.EndsWith(".php"))
            {
                // For PHP files, try to detect injection attempts
                if (ContainsSuspiciousContent(request))
                {
                    Log($"Potential PHP injection attempt from {clientIp}: {path}", LogLevel.Warning);
                    await SendHttpResponseAsync(stream, "500 Internal Server Error", CreateFakeErrorPage(), token);
                }
                else
                {
                    await SendHttpResponseAsync(stream, "404 Not Found", CreateFakeNotFoundPage(), token);
                }
            }
            else
            {
                await SendHttpResponseAsync(stream, "404 Not Found", CreateFakeNotFoundPage(), token);
            }
        }

        private void ExtractCredentials(string request, string clientIp)
        {
            try
            {
                // Check for POST form data
                int bodyStart = request.IndexOf("\r\n\r\n");
                if (bodyStart > 0)
                {
                    string body = request.Substring(bodyStart).Trim();
                    Dictionary<string, string> formData = ParseFormData(body);
                    
                    StringBuilder credentialInfo = new StringBuilder();
                    credentialInfo.AppendLine($"!!! CREDENTIALS CAPTURED from {clientIp} !!!");
                    
                    foreach (var item in formData)
                    {
                        if (item.Key.Contains("user") || item.Key.Contains("email") || 
                            item.Key.Contains("login") || item.Key.Contains("pass"))
                        {
                            credentialInfo.AppendLine($"{item.Key}: {item.Value}");
                        }
                    }
                    
                    Log(credentialInfo.ToString(), LogLevel.Warning);
                }
            }
            catch (Exception ex)
            {
                Log($"Error extracting credentials: {ex.Message}", LogLevel.Error);
            }
        }

        private Dictionary<string, string> ParseFormData(string body)
        {
            Dictionary<string, string> result = new Dictionary<string, string>();
            
            string[] pairs = body.Split('&');
            foreach (string pair in pairs)
            {
                string[] keyValue = pair.Split('=');
                if (keyValue.Length == 2)
                {
                    string key = Uri.UnescapeDataString(keyValue[0]);
                    string value = Uri.UnescapeDataString(keyValue[1]);
                    result[key] = value;
                }
            }
            
            return result;
        }

        private async Task HandleSshAttemptAsync(NetworkStream stream, string request, string clientIp, CancellationToken token)
        {
            Log($"SSH connection attempt from {clientIp}", LogLevel.Warning);
            
            // Send SSH banner and wait for auth attempt
            string sshBanner = "SSH-2.0-OpenSSH_7.4\r\n";
            byte[] bannerBytes = Encoding.ASCII.GetBytes(sshBanner);
            await stream.WriteAsync(bannerBytes, 0, bannerBytes.Length, token);
            
            // In a real honeypot, we'd continue the SSH handshake and try to capture login attempts
            // For our purposes, we'll just keep the connection open for a bit
            await Task.Delay(5000, token);
        }

        private async Task HandleFtpAttemptAsync(NetworkStream stream, string request, string clientIp, CancellationToken token)
        {
            Log($"FTP connection attempt from {clientIp}", LogLevel.Warning);
            
            // Send FTP welcome banner
            string ftpBanner = "220 FTP Server Ready.\r\n";
            byte[] bannerBytes = Encoding.ASCII.GetBytes(ftpBanner);
            await stream.WriteAsync(bannerBytes, 0, bannerBytes.Length, token);
            
            // Extract username if present
            if (request.Contains("USER"))
            {
                Match match = Regex.Match(request, @"USER\s+(\S+)");
                if (match.Success)
                {
                    string username = match.Groups[1].Value;
                    Log($"FTP login attempt with username: {username} from {clientIp}", LogLevel.Warning);
                    
                    // Prompt for password
                    string passPrompt = "331 Password required for " + username + "\r\n";
                    byte[] passPromptBytes = Encoding.ASCII.GetBytes(passPrompt);
                    await stream.WriteAsync(passPromptBytes, 0, passPromptBytes.Length, token);
                    
                    // Try to read password
                    byte[] buffer = new byte[1024];
                    int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, token);
                    if (bytesRead > 0)
                    {
                        string passResponse = Encoding.ASCII.GetString(buffer, 0, bytesRead).Trim();
                        Match passMatch = Regex.Match(passResponse, @"PASS\s+(\S+)");
                        if (passMatch.Success)
                        {
                            string password = passMatch.Groups[1].Value;
                            Log($"FTP credentials captured - Username: {username}, Password: {password} from {clientIp}", LogLevel.Alert);
                        }
                    }
                    
                    // Always deny access
                    string denied = "530 Login incorrect.\r\n";
                    byte[] deniedBytes = Encoding.ASCII.GetBytes(denied);
                    await stream.WriteAsync(deniedBytes, 0, deniedBytes.Length, token);
                }
            }
            
            // Keep connection open for a bit
            await Task.Delay(2000, token);
        }

        private async Task HandleUnknownProtocolAsync(NetworkStream stream, string request, string clientIp, CancellationToken token)
        {
            Log($"Unknown protocol connection from {clientIp}: {request.Substring(0, Math.Min(50, request.Length))}", LogLevel.Info);
            
            // For most unknown protocols, just keeping the connection open to gather more data is best
            await Task.Delay(3000, token);
            
            // Send a generic response
            string response = "Server: Connection established.\r\n";
            byte[] responseBytes = Encoding.ASCII.GetBytes(response);
            await stream.WriteAsync(responseBytes, 0, responseBytes.Length, token);
        }

        private async Task SendHttpResponseAsync(NetworkStream stream, string status, string content, CancellationToken token)
        {
            StringBuilder response = new StringBuilder();
            response.AppendLine($"HTTP/1.1 {status}");
            response.AppendLine("Server: Apache/2.4.41 (Ubuntu)");
            response.AppendLine("Content-Type: text/html; charset=UTF-8");
            response.AppendLine($"Date: {DateTime.UtcNow:R}");
            response.AppendLine($"Content-Length: {Encoding.UTF8.GetByteCount(content)}");
            response.AppendLine("Connection: close");
            response.AppendLine();
            response.Append(content);
            
            byte[] responseBytes = Encoding.UTF8.GetBytes(response.ToString());
            await stream.WriteAsync(responseBytes, 0, responseBytes.Length, token);
            await stream.FlushAsync(token);
        }

        private string CreateFakeHomepage()
        {
            return @"<!DOCTYPE html>
<html>
<head>
    <title>Company Intranet</title>
    <meta name=""viewport"" content=""width=device-width, initial-scale=1"">
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; }
        .header { background-color: #2c3e50; color: white; padding: 1em; }
        .nav { background-color: #34495e; padding: 0.5em; color: white; }
        .nav a { color: white; margin: 0 1em; text-decoration: none; }
        .main { padding: 1em; }
        .footer { background-color: #2c3e50; color: white; text-align: center; padding: 1em; position: fixed; bottom: 0; width: 100%; }
    </style>
</head>
<body>
    <div class=""header"">
        <h1>ACME Corporation Intranet</h1>
    </div>
    <div class=""nav"">
        <a href=""/"">Home</a>
        <a href=""/news"">News</a>
        <a href=""/departments"">Departments</a>
        <a href=""/login"">Employee Login</a>
        <a href=""/admin"">Admin</a>
    </div>
    <div class=""main"">
        <h2>Company Announcements</h2>
        <p>Welcome to the company intranet. Please log in to access your personal dashboard.</p>
        <h3>Recent Updates</h3>
        <ul>
            <li>Server maintenance scheduled for this weekend</li>
            <li>New security policies in effect starting next month</li>
            <li>Q3 financial reports are now available in the Finance section</li>
        </ul>
    </div>
    <div class=""footer"">
        &copy; 2025 ACME Corporation. All rights reserved.
    </div>
</body>
</html>";
        }

        private string CreateFakeLoginPage()
        {
            return @"<!DOCTYPE html>
<html>
<head>
    <title>Employee Login - Company Intranet</title>
    <meta name=""viewport"" content=""width=device-width, initial-scale=1"">
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; }
        .header { background-color: #2c3e50; color: white; padding: 1em; }
        .login-container { width: 300px; margin: 50px auto; background: white; padding: 20px; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        .login-container h2 { text-align: center; color: #2c3e50; }
        .login-container input[type=""text""], .login-container input[type=""password""] { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 3px; box-sizing: border-box; }
        .login-container input[type=""submit""] { width: 100%; background-color: #2c3e50; color: white; border: none; padding: 10px; border-radius: 3px; cursor: pointer; }
        .login-container input[type=""submit""]:hover { background-color: #34495e; }
        .footer { background-color: #2c3e50; color: white; text-align: center; padding: 1em; position: fixed; bottom: 0; width: 100%; }
    </style>
</head>
<body>
    <div class=""header"">
        <h1>ACME Corporation Intranet</h1>
    </div>
    <div class=""login-container"">
        <h2>Employee Login</h2>
        <form action=""/login"" method=""post"">
            <input type=""text"" name=""username"" placeholder=""Username"" required>
            <input type=""password"" name=""password"" placeholder=""Password"" required>
            <input type=""submit"" value=""Login"">
        </form>
        <p style=""text-align: center; margin-top: 20px;""><a href=""#"">Forgot Password?</a></p>
    </div>
    <div class=""footer"">
        &copy; 2025 ACME Corporation. All rights reserved.
    </div>
</body>
</html>";
        }

        private string CreateFakeLoginFailedPage()
        {
            return @"<!DOCTYPE html>
<html>
<head>
    <title>Login Failed - Company Intranet</title>
    <meta name=""viewport"" content=""width=device-width, initial-scale=1"">
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; }
        .header { background-color: #2c3e50; color: white; padding: 1em; }
        .login-container { width: 300px; margin: 50px auto; background: white; padding: 20px; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        .login-container h2 { text-align: center; color: #2c3e50; }
        .error { color: red; text-align: center; margin-bottom: 15px; }
        .login-container input[type=""text""], .login-container input[type=""password""] { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 3px; box-sizing: border-box; }
        .login-container input[type=""submit""] { width: 100%; background-color: #2c3e50; color: white; border: none; padding: 10px; border-radius: 3px; cursor: pointer; }
        .login-container input[type=""submit""]:hover { background-color: #34495e; }
        .footer { background-color: #2c3e50; color: white; text-align: center; padding: 1em; position: fixed; bottom: 0; width: 100%; }
    </style>
</head>
<body>
    <div class=""header"">
        <h1>ACME Corporation Intranet</h1>
    </div>
    <div class=""login-container"">
        <h2>Employee Login</h2>
        <div class=""error"">Invalid username or password. Please try again.</div>
        <form action=""/login"" method=""post"">
            <input type=""text"" name=""username"" placeholder=""Username"" required>
            <input type=""password"" name=""password"" placeholder=""Password"" required>
            <input type=""submit"" value=""Login"">
        </form>
        <p style=""text-align: center; margin-top: 20px;""><a href=""#"">Forgot Password?</a></p>
    </div>
    <div class=""footer"">
        &copy; 2025 ACME Corporation. All rights reserved.
    </div>
</body>
</html>";
        }

        private string CreateFakeAdminForbiddenPage()
        {
            return @"<!DOCTYPE html>
<html>
<head>
    <title>403 Forbidden</title>
    <meta name=""viewport"" content=""width=device-width, initial-scale=1"">
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; }
        .container { width: 80%; margin: 50px auto; text-align: center; }
        .error-code { font-size: 72px; color: #e74c3c; }
        .error-message { font-size: 24px; color: #333; }
    </style>
</head>
<body>
    <div class=""container"">
        <div class=""error-code"">403</div>
        <div class=""error-message"">Forbidden</div>
        <p>You don't have permission to access this resource.</p>
        <p>This access attempt has been logged and reported to security.</p>
        <p><a href=""/"">Return to Home</a></p>
    </div>
</body>
</html>";
        }

        private string CreateFakeNotFoundPage()
        {
            return @"<!DOCTYPE html>
<html>
<head>
    <title>404 Not Found</title>
    <meta name=""viewport"" content=""width=device-width, initial-scale=1"">
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; }
        .container { width: 80%; margin: 50px auto; text-align: center; }
        .error-code { font-size: 72px; color: #3498db; }
        .error-message { font-size: 24px; color: #333; }
    </style>
</head>
<body>
    <div class=""container"">
        <div class=""error-code"">404</div>
        <div class=""error-message"">Page Not Found</div>
        <p>The page you are looking for might have been removed, had its name changed, or is temporarily unavailable.</p>
        <p><a href=""/"">Return to Home</a></p>
    </div>
</body>
</html>";
        }

private string CreateFakeErrorPage()
{
    // Generate the error reference ID outside the string
    string errorRef = Guid.NewGuid().ToString("N").Substring(0, 8).ToUpper();
    
    return @"<!DOCTYPE html>
<html>
<head>
    <title>500 Internal Server Error</title>
    <meta name=""viewport"" content=""width=device-width, initial-scale=1"">
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; }
        .container { width: 80%; margin: 50px auto; text-align: center; }
        .error-code { font-size: 72px; color: #e74c3c; }
        .error-message { font-size: 24px; color: #333; }
    </style>
</head>
<body>
    <div class=""container"">
        <div class=""error-code"">500</div>
        <div class=""error-message"">Internal Server Error</div>
        <p>The server encountered an unexpected condition that prevented it from fulfilling the request.</p>
        <p>Reference #: ERR_" + errorRef + @"</p>
        <p><a href=""/"">Return to Home</a></p>
    </div>
</body>
</html>";
}

        private string CreateFakeWordpressPage()
        {
            return @"<!DOCTYPE html>
<html>
<head>
    <title>ACME Blog - WordPress Site</title>
    <meta name=""viewport"" content=""width=device-width, initial-scale=1"">
    <meta name=""generator"" content=""WordPress 5.8"">
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; }
        .header { background-color: #21759b; color: white; padding: 1em; }
        .nav { background-color: #464646; padding: 0.5em; color: white; }
        .nav a { color: white; margin: 0 1em; text-decoration: none; }
        .main { padding: 1em; max-width: 1000px; margin: 0 auto; }
        .footer { background-color: #21759b; color: white; text-align: center; padding: 1em; margin-top: 20px; }
    </style>
</head>
<body>
    <div class=""header"">
        <h1>ACME Blog</h1>
        <p>Company News and Updates</p>
    </div>
    <div class=""nav"">
        <a href=""/"">Home</a>
        <a href=""/blog"">Blog</a>
        <a href=""/about"">About</a>
        <a href=""/contact"">Contact</a>
        <a href=""/wp-admin"">Login</a>
    </div>
    <div class=""main"">
        <h2>Recent Posts</h2>
        <article>
            <h3>Company Picnic Announced</h3>
            <p>Posted on April 15, 2025 by admin</p>
            <p>We're excited to announce our annual company picnic will be held next month...</p>
            <a href=""#"">Read More</a>
        </article>
        <hr>
        <article>
            <h3>New Product Launch</h3>
            <p>Posted on April 10, 2025 by marketing</p>
            <p>Our team is proud to announce the launch of our newest product line...</p>
            <a href=""#"">Read More</a>
        </article>
        <hr>
        <article>
            <h3>Q1 Financial Results</h3>
            <p>Posted on April 5, 2025 by finance</p>
            <p>The first quarter results are in, and we've exceeded expectations...</p>
            <a href=""#"">Read More</a>
        </article>
    </div>
    <div class=""footer"">
        <p>&copy; 2025 ACME Corporation. Powered by WordPress.</p>
    </div>
</body>
</html>";
        }

        public void Stop()
        {
            if (!IsRunning || _cts == null || _listener == null)
            {
                Log("Honeypot is not running or already stopped.", LogLevel.Warning);
                return;
            }

            Log("Stopping honeypot...", LogLevel.Info);
            _cts.Cancel(); // Signal cancellation to the tasks
            _listener.Stop(); // Stop listening for new connections
            IsRunning = false; // Set flag immediately

            // Give tasks a moment to finish gracefully
            Task.Delay(1000).Wait();

            _cts.Dispose();
            _cts = null;
            _listener = null;

            // Log statistics
            Log($"Honeypot stopped. Connection statistics:", LogLevel.Info);
            foreach (var stat in _attackerStats.OrderByDescending(s => s.Value))
            {
                Log($"IP: {stat.Key}, Connection attempts: {stat.Value}", LogLevel.Info);
            }
        }

        private enum LogLevel
        {
            Debug,
            Info,
            Warning,
            Error,
            Alert,
            Detail
        }

        private void Log(string message, LogLevel level)
        {
            string prefix = level switch
            {
                LogLevel.Debug => "[DEBUG]",
                LogLevel.Info => "[INFO]",
                LogLevel.Warning => "[WARNING]",
                LogLevel.Error => "[ERROR]",
                LogLevel.Alert => "[ALERT]",
                LogLevel.Detail => "[DETAIL]",
                _ => "[INFO]"
            };

            string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
            string logMessage = $"{timestamp} {prefix} {message}";
            
            // Print to console except details which might be too verbose
            if (level != LogLevel.Detail)
            {
                ConsoleColor originalColor = Console.ForegroundColor;
                
                Console.ForegroundColor = level switch
                {
                    LogLevel.Warning => ConsoleColor.Yellow,
                    LogLevel.Error => ConsoleColor.Red,
                    LogLevel.Alert => ConsoleColor.Magenta,
                    _ => originalColor
                };
                
                Console.WriteLine($"[Honeypot] {logMessage}");
                Console.ForegroundColor = originalColor;
            }

            try
            {
                // Append to log file
                File.AppendAllText(_settings.LogFilePath, logMessage + Environment.NewLine);
                
                // For detailed logs (like captured credentials or attack attempts), 
                // also write to a separate detailed log file
                if (level == LogLevel.Detail || level == LogLevel.Alert)
                {
                    string detailedLogPath = Path.Combine(
                        Path.GetDirectoryName(_settings.LogFilePath) ?? "",
                        "honeypot_detailed_" + DateTime.Now.ToString("yyyyMMdd") + ".log");
                    
                    File.AppendAllText(detailedLogPath, logMessage + Environment.NewLine);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Honeypot] Failed to write to log file: {ex.Message}");
            }
        }
    }
}