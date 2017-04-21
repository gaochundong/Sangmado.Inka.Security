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

            Test_SHA1withRSA_Sign_Verify(privateKeyXmlString, publicKeyXmlString);
        }

        public static void Test_SHA1withRSA_Sign_Verify(string privateKeyXmlString, string publicKeyXmlString)
        {
            string content = @"Hello World";
            byte[] buffer = Encoding.UTF8.GetBytes(content);

            string signature = SHA1withRSA.Sign(privateKeyXmlString, buffer);
            bool verified = SHA1withRSA.Verify(publicKeyXmlString, buffer, signature);

            Console.WriteLine(verified);
        }
    }
}
