using System;
using System.Collections.Generic;
using System.Net.Mail;

namespace RockStone.Inka.Security
{
    public static class EmailValidator
    {
        public static bool Validate(string email, out ICollection<string> errors)
        {
            errors = new List<string>();

            if (string.IsNullOrWhiteSpace(email))
            {
                errors.Add("The email cannot be empty or whitespace.");
            }
            else
            {
                try
                {
                    var m = new MailAddress(email);
                }
                catch (FormatException)
                {
                    errors.Add("Invalid email format.");
                }
            }

            return errors.Count == 0;
        }
    }
}
