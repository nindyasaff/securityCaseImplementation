using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace packetData
{
    public class AesEncryptor
    {
        public Aes aes;

        public AesEncryptor()
        {
            byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            aes = Aes.Create();
            aes.IV = iv;
        }

        public void GenerateNewKey()
        {
            aes.GenerateKey();
            Console.WriteLine($"New Key: {Convert.ToBase64String(aes.Key)}");
        }

        public void SetKey(byte[] key)
        {
            aes.Key = key;
            Console.WriteLine($"Updated Key: {Convert.ToBase64String(aes.Key)}");
        }

        public string Encrypt(string plainText)
        {
            byte[] encrypted;

            ICryptoTransform enc = aes.CreateEncryptor();

            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, enc, CryptoStreamMode.Write))
                {
                    using (StreamWriter sw = new StreamWriter(cs))
                    {
                        sw.Write(plainText);
                    }

                    encrypted = ms.ToArray();
                }
            }

            return Convert.ToBase64String(encrypted);
        }

        public string Decrypt(string encryptedText)
        {
            string decrypted = string.Empty;
            byte[] cypher = Convert.FromBase64String(encryptedText);

            ICryptoTransform dec = aes.CreateDecryptor();

            using (MemoryStream ms = new MemoryStream(cypher))
            {
                using (CryptoStream cs = new CryptoStream(ms, dec, CryptoStreamMode.Read))
                {
                    using (StreamReader sr = new StreamReader(cs))
                    {
                        decrypted = sr.ReadToEnd();
                    }
                }
            }

            return decrypted;
        }
    }
}