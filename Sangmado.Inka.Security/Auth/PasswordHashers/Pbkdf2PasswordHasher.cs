using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Sangmado.Inka.Security.Cryptography.KeyDerivation;

namespace Sangmado.Inka.Security
{
    public class Pbkdf2PasswordHasher : IPasswordHasher
    {
        private readonly int _iterCount = 10000;
        private readonly RandomNumberGenerator _rng = RandomNumberGenerator.Create();
        private readonly ManagedPbkdf2Provider _pbdkf2Provider = new ManagedPbkdf2Provider();

        public Pbkdf2PasswordHasher()
        {
        }

        public string HashPassword(string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentNullException("password");
            }

            /* =======================
             * HASHED PASSWORD FORMATS
             * =======================
             * 
             * PBKDF2 with HMAC-SHA256, 128-bit salt, 256-bit subkey, 10000 iterations.
             * Format: { 0x01, prf (UInt32), iter count (UInt32), salt length (UInt32), salt, subkey }
             * (All UInt32s are stored big-endian.)
             */
            var hashing = ComputeHash(
                password,
                prf: KeyDerivationPrf.HMACSHA256,
                iterCount: _iterCount,
                saltSize: 128 / 8,
                numBytesRequested: 256 / 8);
            var hashpass = Convert.ToBase64String(hashing);
            return hashpass;
        }

        private byte[] ComputeHash(string password, KeyDerivationPrf prf, int iterCount, int saltSize, int numBytesRequested)
        {
            byte[] salt = new byte[saltSize];
            _rng.GetBytes(salt);

            byte[] subkey = _pbdkf2Provider.DeriveKey(password, salt, prf, iterCount, numBytesRequested);

            var outputBytes = new byte[13 + salt.Length + subkey.Length];
            outputBytes[0] = 0x01; // format marker -- version

            WriteNetworkByteOrder(outputBytes, 1, (uint)prf);
            WriteNetworkByteOrder(outputBytes, 5, (uint)iterCount);
            WriteNetworkByteOrder(outputBytes, 9, (uint)saltSize);

            Buffer.BlockCopy(salt, 0, outputBytes, 13, salt.Length);
            Buffer.BlockCopy(subkey, 0, outputBytes, 13 + saltSize, subkey.Length);

            return outputBytes;
        }

        public PasswordVerificationResult VerifyHashedPassword(string hashedPassword, string providedPassword)
        {
            if (hashedPassword == null)
            {
                throw new ArgumentNullException("hashedPassword");
            }
            if (providedPassword == null)
            {
                throw new ArgumentNullException("providedPassword");
            }

            byte[] decodedHashedPassword = Convert.FromBase64String(hashedPassword);
            if (decodedHashedPassword == null || decodedHashedPassword.Length == 0)
            {
                return PasswordVerificationResult.Failed;
            }

            // read the format marker from the hashed password
            switch (decodedHashedPassword[0])
            {
                case 0x01:
                    int embeddedIterCount;
                    if (VerifyHashedPassword(decodedHashedPassword, providedPassword, out embeddedIterCount))
                    {
                        // If this hasher was configured with a higher iteration count, change the entry now.
                        return (embeddedIterCount < _iterCount)
                            ? PasswordVerificationResult.SuccessRehashNeeded
                            : PasswordVerificationResult.Success;
                    }
                    else
                    {
                        return PasswordVerificationResult.Failed;
                    }

                default:
                    return PasswordVerificationResult.Failed; // unknown format marker
            }
        }

        private bool VerifyHashedPassword(byte[] hashedPassword, string password, out int iterCount)
        {
            iterCount = default(int);

            try
            {
                // Read header information
                KeyDerivationPrf prf = (KeyDerivationPrf)ReadNetworkByteOrder(hashedPassword, 1);
                iterCount = (int)ReadNetworkByteOrder(hashedPassword, 5);
                int saltLength = (int)ReadNetworkByteOrder(hashedPassword, 9);

                // Read the salt: must be >= 128 bits
                if (saltLength < 128 / 8)
                {
                    return false;
                }
                byte[] salt = new byte[saltLength];
                Buffer.BlockCopy(hashedPassword, 13, salt, 0, salt.Length);

                // Read the subkey (the rest of the payload): must be >= 128 bits
                int subkeyLength = hashedPassword.Length - 13 - salt.Length;
                if (subkeyLength < 128 / 8)
                {
                    return false;
                }
                byte[] expectedSubkey = new byte[subkeyLength];
                Buffer.BlockCopy(hashedPassword, 13 + salt.Length, expectedSubkey, 0, expectedSubkey.Length);

                // Hash the incoming password and verify it
                byte[] actualSubkey = _pbdkf2Provider.DeriveKey(password, salt, prf, iterCount, subkeyLength);

                return ByteArraysEqual(actualSubkey, expectedSubkey);
            }
            catch
            {
                // This should never occur except in the case of a malformed payload, where
                // we might go off the end of the array. Regardless, a malformed payload
                // implies verification failed.
                return false;
            }
        }

        private static uint ReadNetworkByteOrder(byte[] buffer, int offset)
        {
            return ((uint)(buffer[offset + 0]) << 24)
                | ((uint)(buffer[offset + 1]) << 16)
                | ((uint)(buffer[offset + 2]) << 8)
                | ((uint)(buffer[offset + 3]));
        }

        private static void WriteNetworkByteOrder(byte[] buffer, int offset, uint value)
        {
            buffer[offset + 0] = (byte)(value >> 24);
            buffer[offset + 1] = (byte)(value >> 16);
            buffer[offset + 2] = (byte)(value >> 8);
            buffer[offset + 3] = (byte)(value >> 0);
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
