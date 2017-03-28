
using System;

namespace Sangmado.Inka.Security
{
    public interface ISecurityTokenProvider
    {
        string Generate(byte[] secretKey, string modifier = null, TimeSpan? expiredTimeSpan = null);
        bool Validate(int securityToken, byte[] secretKey, string modifier = null, TimeSpan? expiredTimeSpan = null);
    }
}
