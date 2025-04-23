using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json; // Using System.Text.Json
using System.Linq;

namespace CyberUtils
{
    public class IntegrityCheckerService
    {
        private readonly IntegrityCheckerSettings _settings;
        private readonly FileOperationsService _fileFinderHelper; // Reuse file finding

        public IntegrityCheckerService(IntegrityCheckerSettings settings)
        {
            _settings = settings ?? throw new ArgumentNullException(nameof(settings));
             if (string.IsNullOrWhiteSpace(_settings.DirectoryToMonitor) || !Directory.Exists(_settings.DirectoryToMonitor))
            {
                throw new ArgumentException($"DirectoryToMonitor '{_settings.DirectoryToMonitor}' is invalid or does not exist. Check configuration.");
            }
             if (string.IsNullOrWhiteSpace(_settings.BaselineFilePath))
            {
                throw new ArgumentException("BaselineFilePath cannot be empty. Check configuration.");
             }
             // Create a helper FileOperationsService instance JUST for finding files in the monitored dir
            // This avoids needing the encryption key or target dir settings here
             var finderSettings = new FileOperationsSettings { TargetDirectory = _settings.DirectoryToMonitor };
             _fileFinderHelper = new FileOperationsService(finderSettings);
        }

        // Dictionary to store baseline: FilePath -> Hash
        private Dictionary<string, string> LoadBaseline()
        {
            if (!File.Exists(_settings.BaselineFilePath))
            {
                return new Dictionary<string, string>(); // Return empty if baseline doesn't exist
            }

            try
            {
                string json = File.ReadAllText(_settings.BaselineFilePath);
                var baseline = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
                return baseline ?? new Dictionary<string, string>();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading baseline file '{_settings.BaselineFilePath}': {ex.Message}");
                return new Dictionary<string, string>(); // Return empty on error
            }
        }

        private bool SaveBaseline(Dictionary<string, string> baseline)
        {
            try
            {
                var options = new JsonSerializerOptions { WriteIndented = true }; // Pretty print JSON
                string json = JsonSerializer.Serialize(baseline, options);
                File.WriteAllText(_settings.BaselineFilePath, json);
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error saving baseline file '{_settings.BaselineFilePath}': {ex.Message}");
                return false;
            }
        }

        private string CalculateSHA256(string filePath)
        {
            try
            {
                using (var sha256 = SHA256.Create())
                {
                    // Use FileStream with buffer for potentially large files
                     using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, bufferSize: 4096))
                     {
                         byte[] hashBytes = sha256.ComputeHash(stream);
                         // Convert byte array to a hexadecimal string
                        StringBuilder builder = new StringBuilder();
                        foreach(byte b in hashBytes)
                        {
                             builder.Append(b.ToString("x2")); // Lowercase hex
                        }
                         return builder.ToString();
                     }
                }
            }
             catch (IOException ex)
             {
                 Console.WriteLine($"Warning: Could not read file '{filePath}' for hashing (locked?): {ex.Message}");
                 return "ERROR_READING_FILE";
             }
             catch (UnauthorizedAccessException ex)
             {
                 Console.WriteLine($"Warning: Access denied for file '{filePath}' during hashing: {ex.Message}");
                 return "ERROR_ACCESS_DENIED";
             }
            catch (Exception ex) // Other potential errors
             {
                 Console.WriteLine($"Warning: Failed to hash file '{filePath}': {ex.Message}");
                 return "ERROR_HASHING_FAILED";
             }
        }

        public void CreateBaseline()
        {
            Console.WriteLine($"\n--- Creating Integrity Baseline for [{_settings.DirectoryToMonitor}] ---");
            var baseline = new Dictionary<string, string>();
            int count = 0;

            foreach (string file in _fileFinderHelper.GetAllFilesRecursive())
            {
                string hash = CalculateSHA256(file);
                 // Only add to baseline if hashing was successful
                 if (!hash.StartsWith("ERROR_"))
                 {
                    string relativePath = Path.GetRelativePath(_settings.DirectoryToMonitor, file);
                     baseline[relativePath] = hash;
                     Console.WriteLine($"Added: {relativePath} | Hash: {hash.Substring(0, 8)}..."); // Show partial hash
                    count++;
                 }
            }

            if (SaveBaseline(baseline))
            {
                Console.WriteLine($"--- Baseline created successfully with {count} files. Saved to: {_settings.BaselineFilePath} ---");
            }
            else
            {
                Console.WriteLine($"--- Failed to save baseline file. ---");
            }
        }

        public void VerifyIntegrity()
        {
            Console.WriteLine($"\n--- Verifying File Integrity for [{_settings.DirectoryToMonitor}] ---");
            var baseline = LoadBaseline();
            var currentHashes = new Dictionary<string, string>();
            var modifiedFiles = new List<string>();
            var newFiles = new List<string>();
            var deletedFiles = new List<string>(baseline.Keys); // Start with all baseline files as potentially deleted

             if (baseline.Count == 0 && File.Exists(_settings.BaselineFilePath))
            {
                Console.WriteLine("Warning: Loaded baseline is empty. Was it created successfully?");
                // Decide if you want to stop or continue. We continue here.
            }
            else if (baseline.Count == 0)
            {
                 Console.WriteLine("Baseline file not found or is empty. Please create a baseline first.");
                 return;
            }

             int processedCount = 0;
            // Calculate current hashes
            foreach (string file in _fileFinderHelper.GetAllFilesRecursive())
            {
                 processedCount++;
                 string relativePath = Path.GetRelativePath(_settings.DirectoryToMonitor, file);
                string currentHash = CalculateSHA256(file);

                 if (!currentHash.StartsWith("ERROR_"))
                 {
                    currentHashes[relativePath] = currentHash;
                 }
                else
                {
                    Console.WriteLine($"Warning: Could not hash current file: {relativePath}. Skipping check.");
                     // How to handle files that can't be hashed now but were in baseline? Mark as modified?
                     if(baseline.ContainsKey(relativePath))
                     {
                         modifiedFiles.Add($"{relativePath} (Hashing Error)");
                        deletedFiles.Remove(relativePath); // Not technically deleted if it exists but can't be hashed
                     } else {
                        newFiles.Add($"{relativePath} (Hashing Error)"); // Treat as new if not in baseline and unhashable
                    }
                }
            }

            // Compare current state with baseline
            foreach (var kvp in currentHashes)
            {
                string relativePath = kvp.Key;
                string currentHash = kvp.Value;

                if (baseline.TryGetValue(relativePath, out string? baselineHash)) // Use TryGetValue
                {
                    deletedFiles.Remove(relativePath); // File exists, so not deleted
                    if (!string.Equals(currentHash, baselineHash, StringComparison.OrdinalIgnoreCase))
                    {
                        modifiedFiles.Add($"{relativePath} (Expected: {baselineHash.Substring(0,8)}..., Found: {currentHash.Substring(0,8)}...)");
                    }
                     // else: Hash matches, file is unchanged - do nothing
                }
                else
                {
                    newFiles.Add(relativePath); // File exists now but wasn't in baseline
                }
            }

            // --- Report Results ---
            bool noChanges = modifiedFiles.Count == 0 && newFiles.Count == 0 && deletedFiles.Count == 0;

            if (noChanges)
            {
                 Console.WriteLine($"--- Verification complete. No changes detected ({processedCount} files checked). ---");
            }
            else
            {
                 Console.WriteLine($"--- Verification complete. Changes detected: ---");

                 if (modifiedFiles.Count > 0)
                {
                     Console.WriteLine($"\n[!] Modified Files ({modifiedFiles.Count}):");
                     modifiedFiles.ForEach(f => Console.WriteLine($"  - {f}"));
                 }
                 if (newFiles.Count > 0)
                 {
                     Console.WriteLine($"\n[+] New Files ({newFiles.Count}):");
                     newFiles.ForEach(f => Console.WriteLine($"  - {f}"));
                 }
                 if (deletedFiles.Count > 0)
                {
                    Console.WriteLine($"\n[-] Deleted Files ({deletedFiles.Count}):");
                     deletedFiles.ForEach(f => Console.WriteLine($"  - {f}"));
                }
                Console.WriteLine("--- End of Verification Report ---");
             }
        }
    }
}