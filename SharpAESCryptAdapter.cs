using System;
using SharpAESCrypt;

namespace CyberUtils
{
    // Adapter class to make SharpAESCrypt work with our existing code structure
    public static class SharpAESCrypt
    {
        public static void Encrypt(string password, string sourceFile, string destFile)
        {
            SharpAESCrypt.Encrypt(password, sourceFile, destFile);
        }

        public static void Decrypt(string password, string sourceFile, string destFile)
        {
            SharpAESCrypt.Decrypt(password, sourceFile, destFile);
        }
        
        // Exception classes for compatibility
        public class WrongPasswordException : Exception
        {
            public WrongPasswordException(string message) : base(message) { }
        }

        public class PayloadCorruptedException : Exception
        {
            public PayloadCorruptedException(string message) : base(message) { }
        }
    }
}