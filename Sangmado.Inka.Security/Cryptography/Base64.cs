using System;
using System.Text;

namespace Sangmado.Inka.Security
{
    public static class Base64
    {
        public static string Encode(string password)
        {
            return Convert.ToBase64String(Encoding.Unicode.GetBytes(password));
        }

        public static string Decode(string hashedPassword)
        {
            return Encoding.Unicode.GetString(Convert.FromBase64String(hashedPassword));
        }
    }
}
