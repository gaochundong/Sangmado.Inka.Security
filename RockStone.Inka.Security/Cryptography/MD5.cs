using System;
using System.Security.Cryptography;
using System.Text;

namespace RockStone.Inka.Security
{
    public static class MD5
    {
        private static HashAlgorithm _hasher = System.Security.Cryptography.MD5.Create();

        public static string GetBufferHash(byte[] buffer)
        {
            return GetBufferHash(buffer, 0, buffer.Length);
        }

        public static string GetBufferHash(byte[] buffer, int count)
        {
            return GetBufferHash(buffer, 0, count);
        }

        public static string GetBufferHash(byte[] buffer, int offset, int count)
        {
            var hash = _hasher.ComputeHash(buffer, offset, count);
            return ConvertToHexadecimalString(hash, 0, hash.Length);
        }

        public static string ConvertToHexadecimalString(byte[] hash)
        {
            return ConvertToHexadecimalString(hash, 0, hash.Length);
        }

        public static string ConvertToHexadecimalString(byte[] hash, int count)
        {
            return ConvertToHexadecimalString(hash, 0, count);
        }

        public static string ConvertToHexadecimalString(byte[] hash, int offset, int count)
        {
            var sb = new StringBuilder();
            for (int i = offset; i < hash.Length && i < offset + count; i++)
            {
                sb.Append(hash[i].ToString("x2"));
            }
            return sb.ToString();
        }

        public static bool Validate(byte[] buffer, string checksum)
        {
            return Validate(buffer, 0, buffer.Length, checksum);
        }

        public static bool Validate(byte[] buffer, int count, string checksum)
        {
            return Validate(buffer, 0, count, checksum);
        }

        public static bool Validate(byte[] buffer, int offset, int count, string checksum)
        {
            var hash = GetBufferHash(buffer, offset, count);

            StringComparer comparer = StringComparer.OrdinalIgnoreCase;
            if (0 == comparer.Compare(checksum, hash))
                return true;
            else
                return false;
        }
    }
}
