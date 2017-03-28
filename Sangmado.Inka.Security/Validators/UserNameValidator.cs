using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace Sangmado.Inka.Security
{
    public class UserNameOptions
    {
        public UserNameOptions()
        {
            RequiredLength = 5;
        }

        public int RequiredLength { get; set; }
    }

    public static class UserNameValidator
    {
        public const string UserNameValidationRegex = "^[a-zA-Z0-9@_\\.]+$";
        public static readonly TimeSpan UserNameValidationRegexTimeout = new TimeSpan(0, 0, 0, 0, 20);
        private static readonly UserNameOptions _defaultOptions = new UserNameOptions();

        public static bool Validate(string userName, out ICollection<string> errors)
        {
            return Validate(userName, _defaultOptions, out errors);
        }

        public static bool Validate(string userName, UserNameOptions options, out ICollection<string> errors)
        {
            errors = new List<string>();

            try
            {
                if (string.IsNullOrWhiteSpace(userName) || userName.Length < options.RequiredLength)
                {
                    errors.Add("The username is too short.");
                }
                else if (!Regex.IsMatch(userName, UserNameValidationRegex, RegexOptions.CultureInvariant, UserNameValidationRegexTimeout))
                {
                    errors.Add("The username is invalid.");
                }
            }
            catch (RegexMatchTimeoutException)
            {
                errors.Add("The username is invalid.");
            }

            return errors.Count == 0;
        }
    }
}
