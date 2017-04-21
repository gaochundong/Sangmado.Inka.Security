using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace Sangmado.Inka.Security.TestConsole
{
    class Program
    {
        static void Main(string[] args)
        {
            string privateKeyText = File.ReadAllText(Environment.CurrentDirectory + @"\PEMKeys\app_private_key.pem");
            string publicKeyText = File.ReadAllText(Environment.CurrentDirectory + @"\PEMKeys\app_public_key.pem");

            PemReader privateKeyPemReader = new PemReader(new StringReader(privateKeyText));
            RsaPrivateCrtKeyParameters privateKey = (privateKeyPemReader.ReadObject() as AsymmetricCipherKeyPair).Private as RsaPrivateCrtKeyParameters;

            PemReader publicKeyPemReader = new PemReader(new StringReader(publicKeyText));
            RsaKeyParameters publicKey = publicKeyPemReader.ReadObject() as RsaKeyParameters;

            var privateKeyXmlString = DotNetUtilities.ToRSA(privateKey).ToXmlString(true);
            var publicKeyXmlString = DotNetUtilities.ToRSA(publicKey).ToXmlString(false);

            var verified1 = Test_SHA1withRSA_Sign_Verify(privateKeyXmlString, publicKeyXmlString);
            var verified2 = Test_SHA1withRSA_Sign_With_BouncyCastle_Then_Verify_With_DotNet(privateKey, publicKeyXmlString);
            var verified3 = Test_SHA1withRSA_Sign_With_DotNet_Then_Verify_With_BouncyCastle(privateKeyXmlString, publicKey);

            Console.WriteLine("{0}, {1}, {2}", verified1, verified2, verified3);
        }

        public static bool Test_SHA1withRSA_Sign_Verify(
            string privateKeyXmlString, string publicKeyXmlString)
        {
            string content = @"Hello World";
            byte[] buffer = Encoding.UTF8.GetBytes(content);

            string signature = SHA1withRSA.Sign(privateKeyXmlString, buffer);
            bool verified = SHA1withRSA.Verify(publicKeyXmlString, buffer, signature);

            return verified;
        }

        public static bool Test_SHA1withRSA_Sign_With_BouncyCastle_Then_Verify_With_DotNet(
            RsaPrivateCrtKeyParameters rsaPrivate, string publicKeyXmlString)
        {
            string content = @"Hello World";
            byte[] buffer = Encoding.UTF8.GetBytes(content);

            var signer = SignerUtilities.GetSigner(@"SHA-1withRSA");
            signer.Init(true, rsaPrivate);
            signer.BlockUpdate(buffer, 0, buffer.Length);
            byte[] signedHash = signer.GenerateSignature();

            string signature = Convert.ToBase64String(signedHash);

            bool verified = SHA1withRSA.Verify(publicKeyXmlString, buffer, signature);

            return verified;
        }

        public static bool Test_SHA1withRSA_Sign_With_DotNet_Then_Verify_With_BouncyCastle(
            string privateKeyXmlString, RsaKeyParameters rsaPublic)
        {
            string content = @"Hello World";
            byte[] buffer = Encoding.UTF8.GetBytes(content);

            string signature = SHA1withRSA.Sign(privateKeyXmlString, buffer);

            var signer = SignerUtilities.GetSigner(@"SHA-1withRSA");
            signer.Init(false, rsaPublic);
            signer.BlockUpdate(buffer, 0, buffer.Length);

            byte[] signedHash = Convert.FromBase64String(signature);
            bool verified = signer.VerifySignature(signedHash);

            return verified;
        }
    }
}
