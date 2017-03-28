using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace Sangmado.Inka.Security
{
    public static class PhoneNumberValidator
    {
        private const string _chinaPhoneNumberPattern = @"^\d{11}$";

        public static bool ValidateChinaPhoneNumber(string phoneNumber, out ICollection<string> errors)
        {
            errors = new List<string>();

            if (string.IsNullOrWhiteSpace(phoneNumber))
            {
                errors.Add("The phone number cannot be empty or whitespace.");
            }
            else
            {
                if (!Regex.IsMatch(phoneNumber, _chinaPhoneNumberPattern))
                {
                    errors.Add("Invalid phone number format.");
                }
            }

            return errors.Count == 0;
        }
    }
}
