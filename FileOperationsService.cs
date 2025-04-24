using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security; // For SecurityException
using SharpAESCrypt; 

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


        // --- ENCRYPTOR (Enhanced Version) ---
        public void EncryptFiles()
        {
            Console.WriteLine($"\n--- Encrypting Files in [{_settings.TargetDirectory}] with extension '{EncryptedFileExtension}' ---");
            string tempDir = GetSafeTempDirectory();

            int processedCount = 0;
            int encryptedCount = 0;
            int skippedCount = 0;
            int errorCount = 0;

            var filesToProcess = GetAllFilesRecursive();
            if (!filesToProcess.Any())
            {
                 Console.WriteLine("No files found to process in the target directory.");
                 return;
            }


            foreach (string sourceFilePath in filesToProcess)
            {
                 processedCount++;
                string targetFilePathWithExt = sourceFilePath + EncryptedFileExtension;

                // 1. Skip already encrypted files (based on extension)
                if (sourceFilePath.EndsWith(EncryptedFileExtension, StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine($"Skipping (already has {EncryptedFileExtension}): {sourceFilePath}");
                    skippedCount++;
                    continue;
                }
                // Skip if the target encrypted file *already* exists (e.g. from partial run)
                // This prevents potential overwrite errors if not handled carefully later
                 if (File.Exists(targetFilePathWithExt))
                 {
                    Console.WriteLine($"Skipping (target '{targetFilePathWithExt}' already exists): {sourceFilePath}");
                    skippedCount++;
                    continue;
                 }


                string tempEncryptedFile = Path.Combine(tempDir, Path.GetRandomFileName() + EncryptedFileExtension);
                 string tempVerifyFile = Path.Combine(tempDir, Path.GetRandomFileName() + ".verify");


                Console.WriteLine($"Processing [{processedCount}]: {sourceFilePath}");

                try
                {
                    // 2. Encrypt original to temporary file
                    Console.WriteLine($"  Encrypting -> {Path.GetFileName(tempEncryptedFile)}");
                  SharpAESCrypt.Encrypt(_settings.EncryptionKey, sourceFilePath, tempEncryptedFile);

                    // 3. Verify by decrypting the temporary file
                    Console.WriteLine($"  Verifying -> {Path.GetFileName(tempVerifyFile)}");
                     try
                     {
                    SharpAESCrypt.Decrypt(_settings.EncryptionKey, tempEncryptedFile, tempVerifyFile);
                         Console.WriteLine($"  Verification successful.");
                     }
                    catch(Exception ex)
                     {
                         // If decryption failed (wrong key, corruption), don't proceed!
                         PrintOperationError($"Verification failed for {sourceFilePath}! Original file will NOT be deleted.", sourceFilePath, ex);
                        errorCount++;
                        continue; // Go to finally block, then next file
                     }

                     // 4. Verification succeeded, now commit the changes
                    Console.WriteLine($"  Deleting original: {Path.GetFileName(sourceFilePath)}");
                     File.Delete(sourceFilePath); // Delete the original

                    Console.WriteLine($"  Moving encrypted file to: {Path.GetFileName(targetFilePathWithExt)}");
                     File.Move(tempEncryptedFile, targetFilePathWithExt); // Move the verified encrypted file

                    encryptedCount++;
                    Console.WriteLine($" -> Success: {targetFilePathWithExt}");
                }
                 catch (FileNotFoundException ex) { HandleFileException(ex, "File not found during operation", sourceFilePath, ref errorCount); }
                 catch (UnauthorizedAccessException ex) { HandleFileException(ex, "Access Denied", sourceFilePath, ref errorCount); }
                 catch (SecurityException ex) { HandleFileException(ex, "Security Exception", sourceFilePath, ref errorCount); }
                 catch (IOException ex) { HandleFileException(ex, "IO Error", sourceFilePath, ref errorCount); }
                catch (Exception ex) // Catch-all for SharpAESCrypt or other unexpected errors
                {
                    errorCount++;
                    PrintOperationError($"Encryption process failed.", sourceFilePath, ex);
                }
                finally
                {
                    // 5. Cleanup temporary files reliably
                    CleanupTempFile(tempEncryptedFile);
                     CleanupTempFile(tempVerifyFile);
                 }
            }

             Console.WriteLine($"--- Encryption Summary ---");
             Console.WriteLine($"  Total Files Processed: {processedCount}");
             Console.WriteLine($"  Successfully Encrypted & Verified: {encryptedCount}");
             Console.WriteLine($"  Skipped (Already Encrypted/Exists): {skippedCount}");
             Console.WriteLine($"  Errors: {errorCount}");
             Console.WriteLine($"--------------------------");
        }


        // --- DECRYPTOR (Enhanced Version) ---
        public void DecryptFiles()
        {
            Console.WriteLine($"\n--- Decrypting Files in [{_settings.TargetDirectory}] with extension '{EncryptedFileExtension}' ---");
            string tempDir = GetSafeTempDirectory();

             int processedCount = 0;
            int decryptedCount = 0;
            int skippedCount = 0; // For non-.cbf files
            int errorCount = 0;


             // Get all files, then filter locally for the specific extension
             var allFiles = GetAllFilesRecursive();
            if (!allFiles.Any())
             {
                 Console.WriteLine("No files found to process in the target directory.");
                 return;
             }

             var filesToDecrypt = allFiles
                 .Where(f => f.EndsWith(EncryptedFileExtension, StringComparison.OrdinalIgnoreCase))
                 .ToList(); // Convert to list to avoid issues if collection modified during enumeration (unlikely here but safer)

            skippedCount = allFiles.Count() - filesToDecrypt.Count;

             if (!filesToDecrypt.Any())
             {
                Console.WriteLine($"No files with '{EncryptedFileExtension}' extension found to decrypt.");
                 if(skippedCount > 0) Console.WriteLine($"({skippedCount} other file(s) were skipped)");
                 return;
            }
            if(skippedCount > 0) Console.WriteLine($"({skippedCount} file(s) without {EncryptedFileExtension} extension will be skipped)");

            foreach (string sourceEncryptedFilePath in filesToDecrypt)
            {
                 processedCount++;

                // Determine the original file name (remove .cbf extension)
                string originalFilePath = sourceEncryptedFilePath.Substring(0, sourceEncryptedFilePath.Length - EncryptedFileExtension.Length);

                // Prevent overwriting existing files during decryption? Risky. Error out instead.
                if (File.Exists(originalFilePath))
                {
                     PrintOperationError($"Decrypted file '{originalFilePath}' already exists. Skipping decryption to prevent overwrite.", sourceEncryptedFilePath);
                    errorCount++;
                    continue;
                }


                string tempDecryptedFile = Path.Combine(tempDir, Path.GetRandomFileName());

                 Console.WriteLine($"Processing [{processedCount}/{filesToDecrypt.Count}]: {sourceEncryptedFilePath}");


                try
                {
                    // 1. Decrypt to temporary file
                    Console.WriteLine($"  Decrypting -> {Path.GetFileName(tempDecryptedFile)}");
                     SharpAESCrypt.Decrypt(_settings.EncryptionKey, sourceEncryptedFilePath, tempDecryptedFile);

                    // Simple check if temp file was created
                    if (!File.Exists(tempDecryptedFile))
                     {
                        throw new FileNotFoundException("Decryption process did not create the temporary output file.", tempDecryptedFile);
                     }

                     Console.WriteLine($"  Decryption appears successful.");

                     // 2. Commit: Delete original encrypted file
                    Console.WriteLine($"  Deleting encrypted source: {Path.GetFileName(sourceEncryptedFilePath)}");
                     File.Delete(sourceEncryptedFilePath);

                     // 3. Move temporary decrypted file to final destination
                    Console.WriteLine($"  Moving decrypted file to: {Path.GetFileName(originalFilePath)}");
                     File.Move(tempDecryptedFile, originalFilePath);

                     decryptedCount++;
                     Console.WriteLine($" -> Success: {originalFilePath}");
                }
                 // Specific SharpAESCrypt errors first
                catch (SharpAESCrypt.WrongPasswordException ex)
                {
                     errorCount++;
                     PrintOperationError($"Wrong Password/Key.", sourceEncryptedFilePath, ex);
                 }
                catch (SharpAESCrypt.PayloadCorruptedException ex)
                {
                     errorCount++;
                     PrintOperationError($"Data Corruption detected.", sourceEncryptedFilePath, ex);
                }
                 // IO / System errors
                 catch (FileNotFoundException ex) { HandleFileException(ex, "File not found during operation", sourceEncryptedFilePath, ref errorCount); }
                 catch (UnauthorizedAccessException ex) { HandleFileException(ex, "Access Denied", sourceEncryptedFilePath, ref errorCount); }
                 catch (SecurityException ex) { HandleFileException(ex, "Security Exception", sourceEncryptedFilePath, ref errorCount); }
                 catch (IOException ex) when (ex.Message.Contains("already exists")) // Catch specific move error
                {
                     // This case *should* be caught by our earlier check, but as fallback
                     errorCount++;
                     PrintOperationError($"Decrypted file '{originalFilePath}' already exists. Failed to move temp file.", sourceEncryptedFilePath, ex);
                 }
                catch (IOException ex) { HandleFileException(ex, "IO Error", sourceEncryptedFilePath, ref errorCount); }
                // General catch
                catch (Exception ex)
                {
                    errorCount++;
                     PrintOperationError($"Decryption process failed.", sourceEncryptedFilePath, ex);
                 }
                 finally
                 {
                    // Cleanup temp decrypted file
                     CleanupTempFile(tempDecryptedFile);
                 }
            }

            Console.WriteLine($"--- Decryption Summary ---");
            Console.WriteLine($"  Files with '{EncryptedFileExtension}' Checked: {filesToDecrypt.Count}");
             Console.WriteLine($"  Successfully Decrypted: {decryptedCount}");
            Console.WriteLine($"  Skipped (No {EncryptedFileExtension}): {skippedCount}");
            Console.WriteLine($"  Errors: {errorCount}");
             Console.WriteLine($"--------------------------");
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