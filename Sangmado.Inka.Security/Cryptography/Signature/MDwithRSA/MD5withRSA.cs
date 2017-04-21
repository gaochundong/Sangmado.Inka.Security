using System;
using System.Security.Cryptography;

namespace Sangmado.Inka.Security
{
    public static class MD5withRSA
    {
        public static string Sign(string privateKeyXmlString, byte[] buffer)
        {
            using (HashAlgorithm hashAlgorithm = MD5.Create())
            using (AsymmetricAlgorithm rsa = RSA.Create())
            {
                rsa.FromXmlString(privateKeyXmlString);

                AsymmetricSignatureFormatter signatureFormatter = new RSAPKCS1SignatureFormatter(rsa);
                signatureFormatter.SetHashAlgorithm(@"MD5");

                byte[] hash = hashAlgorithm.ComputeHash(buffer);
                byte[] signedHash = signatureFormatter.CreateSignature(hash);

                return Convert.ToBase64String(signedHash);
            }
        }

        public static bool Verify(string publicKeyXmlString, byte[] buffer, string signature)
        {
            using (HashAlgorithm hashAlgorithm = MD5.Create())
            using (AsymmetricAlgorithm rsa = RSA.Create())
            {
                rsa.FromXmlString(publicKeyXmlString);

                AsymmetricSignatureDeformatter signatureDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
                signatureDeformatter.SetHashAlgorithm(@"MD5");

                byte[] hash = hashAlgorithm.ComputeHash(buffer);
                byte[] signedHash = Convert.FromBase64String(signature);

                return signatureDeformatter.VerifySignature(hash, signedHash);
            }
        }
    }
}
