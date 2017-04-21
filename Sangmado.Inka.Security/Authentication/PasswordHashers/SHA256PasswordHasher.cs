using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace Sangmado.Inka.Security
{
    public class SHA256PasswordHasher : IPasswordHasher
    {
        private static readonly SHA256 _hashAlgorithm = SHA256Managed.Create();
        private string _salt = "Security";

        public SHA256PasswordHasher()
        {
        }

        public SHA256PasswordHasher(string salt)
            : this()
        {
            _salt = salt;
        }

        public string HashPassword(string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentNullException("password");
            }

            var hashing = _hashAlgorithm.ComputeHash(Encoding.Unicode.GetBytes(_salt + password));
            var hashpass = Convert.ToBase64String(hashing);
            return hashpass;
        }

        public PasswordVerificationResult VerifyHashedPassword(string hashedPassword, string providedPassword)
        {
            if (string.IsNullOrEmpty(hashedPassword))
            {
                throw new ArgumentNullException("hashedPassword");
            }
            if (string.IsNullOrEmpty(providedPassword))
            {
                throw new ArgumentNullException("providedPassword");
            }

            byte[] decodedHashedPassword = Convert.FromBase64String(hashedPassword);
            if (decodedHashedPassword == null || decodedHashedPassword.Length == 0)
            {
                return PasswordVerificationResult.Failed;
            }

            var actualBase64Password = HashPassword(providedPassword);
            byte[] actualHashedPassword = Convert.FromBase64String(actualBase64Password);

            if (ByteArraysEqual(decodedHashedPassword, actualHashedPassword))
            {
                return PasswordVerificationResult.Success;
            }
            else
            {
                return PasswordVerificationResult.Failed;
            }
        }

        // Compares two byte arrays for equality. The method is specifically written so that the loop is not optimized.
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        private static bool ByteArraysEqual(byte[] a, byte[] b)
        {
            if (a == null && b == null)
            {
                return true;
            }
            if (a == null || b == null || a.Length != b.Length)
            {
                return false;
            }
            var areSame = true;
            for (var i = 0; i < a.Length; i++)
            {
                areSame &= (a[i] == b[i]);
            }
            return areSame;
        }
    }
}
