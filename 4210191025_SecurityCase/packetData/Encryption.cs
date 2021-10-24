using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Serialization;

namespace packetData
{
   public  class Encryption
    {
        private RSACryptoServiceProvider csp = new RSACryptoServiceProvider();
        public RSAParameters publicKey;
        public RSAParameters privateKey;

        // if data to encrypt is larger than 100 byte, encrypt data per this
        private int sizePerEncrypt = 100;

        public void GetKeySize()
        {
            Console.WriteLine($"{csp.KeySize}");
        }

        public void GenerateKey()
        {
            privateKey = csp.ExportParameters(true);
            publicKey = csp.ExportParameters(false);

        }

        public string ConvertKeyToString(RSAParameters _key)
        {
            var sw = new StringWriter();
            var xs = new XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw, _key);

            return sw.ToString();
        }

        public string Encrypt(string _plainText)
        {
            if (publicKey.Equals(null))
            {
                Console.WriteLine($"public key is null..");
                return null;
            }

            csp = new RSACryptoServiceProvider();
            csp.ImportParameters(publicKey);
            var data = Encoding.Unicode.GetBytes(_plainText);
            int readPos = 0;
            string cypherData = string.Empty;
            while (data.Length - readPos > 0)
            {
                byte[] dataToEncrypt = new byte[100];
                if (data.Length - (readPos + sizePerEncrypt) > 0)
                {
                    Array.Copy(data, readPos, dataToEncrypt, 0, 100);
                    readPos += 100;
                }
                else
                {
                    Array.Copy(data, readPos, dataToEncrypt, 0, data.Length - readPos);
                    readPos = data.Length;
                }

                var encrypted = csp.Encrypt(dataToEncrypt, false);
                cypherData += Convert.ToBase64String(encrypted);
            }

            return cypherData;
        }

        public string Decrypt(string _cypherText)
        {
            if (privateKey.Equals(null))
            {
                Console.WriteLine($"Private Key is null..");
                return null;
            }

            csp = new RSACryptoServiceProvider();
            csp.ImportParameters(privateKey);

            int iteration = _cypherText.Length / 172;
            string resultData = string.Empty;
            for (int i = 0; i < iteration; i++)
            {
                string encriptedKey = _cypherText.Substring(172 * i, 172);
                var byteToDecrypt = Convert.FromBase64String(encriptedKey);
                var plainText = csp.Decrypt(byteToDecrypt, false);
                resultData += Encoding.Unicode.GetString(plainText);
            }

            return resultData.TrimEnd(new[] { '\0' });
        }

    }
}
