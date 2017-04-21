using System;
using System.Security.Cryptography;

namespace Sangmado.Inka.Security
{
    public static class SHA512withRSA
    {
        public static string Sign(string privateKey, byte[] buffer)
        {
            using (HashAlgorithm hashAlgorithm = SHA512.Create())
            using (AsymmetricAlgorithm rsa = RSA.Create())
            {
                rsa.FromXmlString(privateKey);

                AsymmetricSignatureFormatter signatureFormatter = new RSAPKCS1SignatureFormatter(rsa);
                signatureFormatter.SetHashAlgorithm(@"SHA512");

                byte[] hash = hashAlgorithm.ComputeHash(buffer);
                byte[] signedHash = signatureFormatter.CreateSignature(hash);

                return Convert.ToBase64String(signedHash);
            }
        }

        public static bool Verify(string publicKey, byte[] buffer, string signature)
        {
            using (HashAlgorithm hashAlgorithm = SHA512.Create())
            using (AsymmetricAlgorithm rsa = RSA.Create())
            {
                rsa.FromXmlString(publicKey);

                AsymmetricSignatureDeformatter signatureDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
                signatureDeformatter.SetHashAlgorithm(@"SHA512");

                byte[] hash = hashAlgorithm.ComputeHash(buffer);
                byte[] signedHash = Convert.FromBase64String(signature);

                return signatureDeformatter.VerifySignature(hash, signedHash);
            }
        }
    }
}
