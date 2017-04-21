using System;
using System.Globalization;

namespace Sangmado.Inka.Security
{
    public class TotpSecurityStampBasedTokenProvider : ISecurityTokenProvider
    {
        //
        // Parameters:
        //   expiredTimeSpan:
        //     default value is TimeSpan.FromSeconds(90);
        public string Generate(byte[] secretKey, string modifier = null, TimeSpan? expiredTimeSpan = null)
        {
            return Rfc6238AuthenticationService.GenerateSecurityToken(secretKey, modifier, expiredTimeSpan).ToString("D6", CultureInfo.InvariantCulture);
        }

        //
        // Parameters:
        //   expiredTimeSpan:
        //     default value is TimeSpan.FromSeconds(90);
        public bool Validate(int securityToken, byte[] secretKey, string modifier = null, TimeSpan? expiredTimeSpan = null)
        {
            return secretKey != null && Rfc6238AuthenticationService.ValidateSecurityToken(secretKey, securityToken, modifier, expiredTimeSpan);
        }
    }
}
