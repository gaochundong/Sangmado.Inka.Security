using System.Collections.Generic;
using System.Linq;

namespace RockStone.Inka.Security
{
    public class PasswordOptions
    {
        public PasswordOptions()
        {
            RequiredLength = 6;
            RequireNonLetterOrDigit = true;
            RequireLowercase = true;
            RequireUppercase = true;
            RequireDigit = true;
        }

        public int RequiredLength { get; set; }
        public bool RequireNonLetterOrDigit { get; set; }
        public bool RequireLowercase { get; set; }
        public bool RequireUppercase { get; set; }
        public bool RequireDigit { get; set; }
    }

    public static class PasswordValidator
    {
        private static readonly PasswordOptions _defaultOptions = new PasswordOptions();

        public static bool Validate(string password, out ICollection<string> errors)
        {
            return Validate(password, _defaultOptions, out errors);
        }

        public static bool Validate(string password, PasswordOptions options, out ICollection<string> errors)
        {
            errors = new List<string>();

            if (string.IsNullOrWhiteSpace(password) || password.Length < options.RequiredLength)
            {
                errors.Add("The password is too short.");
            }
            if (options.RequireNonLetterOrDigit && password.All(IsLetterOrDigit))
            {
                errors.Add("The password requires non-letter or digit.");
            }
            if (options.RequireDigit && !password.Any(IsDigit))
            {
                errors.Add("The password requires digit.");
            }
            if (options.RequireLowercase && !password.Any(IsLower))
            {
                errors.Add("The password requires lower-case letter.");
            }
            if (options.RequireUppercase && !password.Any(IsUpper))
            {
                errors.Add("The password requires upper-case letter.");
            }

            return errors.Count == 0;
        }

        public static bool IsDigit(char c)
        {
            return c >= '0' && c <= '9';
        }

        public static bool IsLower(char c)
        {
            return c >= 'a' && c <= 'z';
        }

        public static bool IsUpper(char c)
        {
            return c >= 'A' && c <= 'Z';
        }

        public static bool IsLetterOrDigit(char c)
        {
            return IsUpper(c) || IsLower(c) || IsDigit(c);
        }
    }
}
