using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security; // For SecurityException
using System.Security.Cryptography;
using System.Text;

namespace CyberUtils
{
    public class FileOperationsService
    {
        private readonly FileOperationsSettings _settings;
        private const string EncryptedFileExtension = ".cbf"; // Custom extension for encrypted files

        public FileOperationsService(FileOperationsSettings settings)
        {
            _settings = settings ?? throw new ArgumentNullException(nameof(settings));
            if (string.IsNullOrWhiteSpace(_settings.TargetDirectory))
            {
                throw new ArgumentException("TargetDirectory cannot be empty. Check configuration.", nameof(settings.TargetDirectory));
            }
             // Directory existence check deferred to methods that use it, allows service creation even if dir missing initially.
            if (string.IsNullOrWhiteSpace(_settings.EncryptionKey))
            {
                throw new ArgumentException("EncryptionKey cannot be empty. Check configuration.", nameof(settings.EncryptionKey));
            }
        }

        // --- Core Recursive File Finder ---
        // (Same as before, handles exceptions gracefully)
        public IEnumerable<string> GetAllFilesRecursive()
        {
            if (!Directory.Exists(_settings.TargetDirectory))
            {
                Console.WriteLine($"Error: Directory not found: {_settings.TargetDirectory}");
                return Enumerable.Empty<string>();
            }

            try
            {
                // Use EnumerateFiles for better memory efficiency
                return Directory.EnumerateFiles(_settings.TargetDirectory, "*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException ex)
            {
                PrintOperationError($"Access denied while searching directory: {ex.Message}", _settings.TargetDirectory);
                return Enumerable.Empty<string>();
            }
             catch (DirectoryNotFoundException ex) // Could happen in rare cases during enumeration
             {
                 PrintOperationError($"Directory vanished during search?: {ex.Message}", _settings.TargetDirectory);
                 return Enumerable.Empty<string>();
             }
            catch (Exception ex) // Catch other potential exceptions
            {
                PrintOperationError($"An error occurred while searching files: {ex.Message}", _settings.TargetDirectory);
                return Enumerable.Empty<string>();
            }
        }

        // --- Finder (Displays files) ---
        public void FindAndDisplayFiles()
        {
            Console.WriteLine($"\n--- Finding Files in [{_settings.TargetDirectory}] and subdirectories ---");
            int count = 0;
            try
            {
                foreach (string file in GetAllFilesRecursive())
                {
                    Console.WriteLine($"  Found: {file}"); // Indent for clarity
                    count++;
                }
                Console.WriteLine($"--- Found {count} files ---");
            }
            catch (Exception ex) // Should be caught by GetAllFilesRecursive mostly, but belt-and-suspenders
            {
                PrintOperationError($"Error during file listing: {ex.Message}", "(Listing)");
            }
        }

public void DecryptFiles()
{
    Console.WriteLine($"\n--- Decrypting Files in [{_settings.TargetDirectory}] ---");
    
    // Counters for reporting
    int totalFiles = 0;
    int successCount = 0;
    int errorCount = 0;
    
    try
    {
        // Get all encrypted files in the directory (recursively)
        var encryptedFiles = GetAllFilesRecursive()
            .Where(f => Path.GetExtension(f).Equals(EncryptedFileExtension, StringComparison.OrdinalIgnoreCase))
            .ToList();
        
        if (encryptedFiles.Count == 0)
        {
            Console.WriteLine("No encrypted files found.");
            return;
        }
        
        // Process each file
        foreach (string filePath in encryptedFiles)
        {
            totalFiles++;
            
            try
            {
                Console.WriteLine($"Processing [{totalFiles}]: {filePath}");
                
                // Generate output filename (remove .cbf extension)
                string outputFileName = Path.GetFileNameWithoutExtension(filePath);
                string decryptedFilePath = Path.Combine(
                    Path.GetDirectoryName(filePath) ?? _settings.TargetDirectory,
                    outputFileName);
                
                Console.WriteLine($"  Decrypting -> {Path.GetFileName(decryptedFilePath)}");
                
                // Decrypt the file
                DecryptFile(_settings.EncryptionKey, filePath, decryptedFilePath);
// Delete encrypted file only after successful decryption
                File.Delete(filePath);
                
                successCount++;
            }
            catch (Exception ex)
            {
                errorCount++;
                PrintOperationError($"Failed to decrypt file", filePath, ex);
            }
        }
        
        // Final report
        Console.WriteLine($"\n--- Decryption Complete ---");
        Console.WriteLine($"Total files processed: {totalFiles}");
        Console.WriteLine($"Successfully decrypted: {successCount}");
        Console.WriteLine($"Errors encountered: {errorCount}");
    }
    catch (Exception ex)
    {
        PrintOperationError($"An error occurred during decryption process", _settings.TargetDirectory, ex);
        throw;
    }
}

public void EncryptFiles()
{
    Console.WriteLine($"\n--- Encrypting Files in [{_settings.TargetDirectory}] with extension '{EncryptedFileExtension}' ---");
    
    // Counters for reporting
    int totalFiles = 0;
    int successCount = 0;
    int errorCount = 0;
    
    try
    {
        // Get all files in the directory (recursively)
        var allFiles = GetAllFilesRecursive();
        
        // Process each file
        foreach (string filePath in allFiles)
        {
            totalFiles++;
            
            // Skip files that are already encrypted
            if (Path.GetExtension(filePath).Equals(EncryptedFileExtension, StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine($"Skipping already encrypted file: {filePath}");
                continue;
            }
            
            try
            {
                Console.WriteLine($"Processing [{totalFiles}]: {filePath}");
                
                string originalFileName = Path.GetFileName(filePath);
                string originalFileNameBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(originalFileName))
                  .Replace('/', '_').Replace('+', '-').Replace("=", ""); // Make it filesystem-safe
                string encryptedFilePath = Path.Combine(
                Path.GetDirectoryName(filePath) ?? _settings.TargetDirectory,
                 originalFileNameBase64 + EncryptedFileExtension);
                
                Console.WriteLine($"  Encrypting -> {Path.GetFileName(encryptedFilePath)}");
                
                // Encrypt the file
                EncryptFile(_settings.EncryptionKey, filePath, encryptedFilePath);
                
                // Delete original file only after successful encryption
                File.Delete(filePath);
                
                successCount++;
            }
            catch (Exception ex)
            {
                errorCount++;
                PrintOperationError($"Failed to encrypt file", filePath, ex);
            }
        }
        
        // Final report
        Console.WriteLine($"\n--- Encryption Complete ---");
        Console.WriteLine($"Total files processed: {totalFiles}");
        Console.WriteLine($"Successfully encrypted: {successCount}");
        Console.WriteLine($"Errors encountered: {errorCount}");
    }
    catch (Exception ex)
    {
        PrintOperationError($"An error occurred during encryption process", _settings.TargetDirectory, ex);
        throw;
    }
}

        // --- ENCRYPTOR (Enhanced Version) ---
private const int KeySize = 256;
private const int DerivationIterations = 1000;

public void EncryptFile(string password, string sourceFile, string destFile)
{
    try
    {
        byte[] saltBytes = GenerateRandomSalt();
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        
        using (var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, DerivationIterations, HashAlgorithmName.SHA256))
        {
            byte[] keyBytes = key.GetBytes(KeySize / 8);
            using (var aesAlg = Aes.Create())
            {
                aesAlg.Key = keyBytes;
                aesAlg.IV = GenerateRandomIV();
                
                using (FileStream fsInput = new FileStream(sourceFile, FileMode.Open, FileAccess.Read))
                using (FileStream fsOutput = new FileStream(destFile, FileMode.Create))
                {
                    // Write the salt and IV to the beginning of the file
                    fsOutput.Write(BitConverter.GetBytes(saltBytes.Length), 0, 4);
                    fsOutput.Write(saltBytes, 0, saltBytes.Length);
                    fsOutput.Write(BitConverter.GetBytes(aesAlg.IV.Length), 0, 4);
                    fsOutput.Write(aesAlg.IV, 0, aesAlg.IV.Length);

                    // Encrypt
                    using (CryptoStream cryptoStream = new CryptoStream(
                        fsOutput, aesAlg.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        byte[] buffer = new byte[4096];
                        int bytesRead;
                        
                        while ((bytesRead = fsInput.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            cryptoStream.Write(buffer, 0, bytesRead);
                        }
                        
                        cryptoStream.FlushFinalBlock();
                    }
                }
            }
        }
    }
    catch (Exception ex)
    {
        throw new Exception("File encryption failed", ex);
    }
}

// Add these exception classes inside FileOperationsService class
public class WrongPasswordException : Exception
{
    public WrongPasswordException(string message) : base(message) { }
}

public class PayloadCorruptedException : Exception
{
    public PayloadCorruptedException(string message) : base(message) { }
}

public void DecryptFile(string password, string sourceFile, string destFile)
{
    try
    {
        using (FileStream fsInput = new FileStream(sourceFile, FileMode.Open, FileAccess.Read))
        {
            // Read the salt length
            byte[] lenBytes = new byte[4];
            EnsureFullRead(fsInput, lenBytes, 4);
            int saltLength = BitConverter.ToInt32(lenBytes, 0);
            
            // Read the salt
            byte[] saltBytes = new byte[saltLength];
            EnsureFullRead(fsInput, saltBytes, saltLength);

            // Read the IV length
            EnsureFullRead(fsInput, lenBytes, 4);
            int ivLength = BitConverter.ToInt32(lenBytes, 0);
            
            // Read the IV
            byte[] iv = new byte[ivLength];
            EnsureFullRead(fsInput, iv, ivLength);
            
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            
            using (var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, DerivationIterations, HashAlgorithmName.SHA256))
            {
                byte[] keyBytes = key.GetBytes(KeySize / 8);
                using (var aesAlg = Aes.Create())
                {
                    aesAlg.Key = keyBytes;
                    aesAlg.IV = iv;
                    
                    using (FileStream fsOutput = new FileStream(destFile, FileMode.Create))
                    using (CryptoStream cryptoStream = new CryptoStream(
                        fsInput, aesAlg.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        byte[] buffer = new byte[4096];
                        int bytesRead;
                        
                        while ((bytesRead = cryptoStream.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            fsOutput.Write(buffer, 0, bytesRead);
                        }
                    }
                }
            }
        }
    }
    catch (CryptographicException)
    {
        throw new WrongPasswordException("Invalid password or corrupted file");
    }
    catch (Exception ex)
    {
        throw new PayloadCorruptedException($"File decryption failed: {ex.Message}");
    }
}




private void EnsureFullRead(FileStream stream, byte[] buffer, int bytesToRead)
{
    int bytesRead = 0;
    int remainingBytes = bytesToRead;
    
    while (bytesRead < bytesToRead)
    {
        int readNow = stream.Read(buffer, bytesRead, remainingBytes);
        
        if (readNow == 0) // End of stream reached before reading all bytes
            throw new PayloadCorruptedException("Unexpected end of file, the encrypted file appears to be corrupted.");
        
        bytesRead += readNow;
        remainingBytes -= readNow;
    }
}

private byte[] GenerateRandomSalt()
{
    byte[] salt = new byte[32];
    using (var rng = RandomNumberGenerator.Create())
    {
        rng.GetBytes(salt);
    }
    return salt;
}

private byte[] GenerateRandomIV()
{
    using (var aes = Aes.Create())
    {
        aes.GenerateIV();
        return aes.IV;
    }
}


        // --- Helper Methods ---

        

        private string GetSafeTempDirectory()
        {
             string tempDir = _settings.TempDirectory;

             if (string.IsNullOrWhiteSpace(tempDir))
             {
                 return Path.GetTempPath(); // Use system default
            }

             try
            {
                 if (!Directory.Exists(tempDir))
                {
                     Directory.CreateDirectory(tempDir);
                     Console.WriteLine($"Created custom temp directory: {tempDir}");
                }
                 return tempDir;
             }
            catch (Exception ex)
             {
                 PrintOperationError($"Error accessing/creating custom temp directory '{tempDir}'. Using system temp path instead.", tempDir, ex);
                 return Path.GetTempPath(); // Fallback to system temp on error
            }
         }

        private void CleanupTempFile(string filePath)
        {
            if (File.Exists(filePath))
            {
                try
                {
                     File.Delete(filePath);
                    // Console.WriteLine($" Cleaned up temp file: {Path.GetFileName(filePath)}"); // Optional: Verbose cleanup logging
                }
                catch (Exception ex)
                {
                    PrintOperationError($"Failed to clean up temporary file: {filePath}", filePath, ex);
                    // Log or handle inability to clean up temp file if critical
                 }
             }
        }

         private void HandleFileException(Exception ex, string contextMessage, string filePath, ref int errorCounter)
         {
             errorCounter++;
             PrintOperationError(contextMessage, filePath, ex);
         }


        private static void PrintOperationError(string message, string? associatedPath = null, Exception? ex = null)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            string errorMsg = $"Error: {message}";
            if (!string.IsNullOrEmpty(associatedPath)) {
                 errorMsg += $" (File/Path: {associatedPath})";
            }
            if (ex != null)
            {
                // Print basic exception message. Avoid full stack trace unless debugging.
                errorMsg += $" | Details: {ex.GetType().Name} - {ex.Message}";
             }
             Console.WriteLine(errorMsg);
             Console.ResetColor();
         }

    }
}