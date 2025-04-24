using System;

namespace CyberUtils
{
    // Classes to hold settings loaded from appsettings.json
    public class AppSettings
    {
        public FileOperationsSettings FileOperations { get; set; } = new();
        public HoneypotSettings Honeypot { get; set; } = new();
        public IntegrityCheckerSettings IntegrityChecker { get; set; } = new();
    }

    public class FileOperationsSettings
    {
        public string TargetDirectory { get; set; } = string.Empty;
        public string EncryptionKey { get; set; } = string.Empty;
        public string TempDirectory { get; set; } = string.Empty; // Optional: if specified, use this
    }

    public class HoneypotSettings
    {
        public int ListenPort { get; set; } = 2121; // Default port
        public string LogFilePath { get; set; } = "honeypot_log.txt";
    }

    public class IntegrityCheckerSettings
    {
        public string BaselineFilePath { get; set; } = "file_integrity_baseline.json";
        public string DirectoryToMonitor { get; set; } = string.Empty;
    }
}