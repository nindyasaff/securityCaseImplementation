using packetData;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Client
{
    class Client
    {
        private TcpClient socket;
        private NetworkStream stream;

        // assymetric key
        private Encryption clientEncryption = new Encryption();

        string serverPublicKeyPath = Directory.GetCurrentDirectory() + "\\server-public-key.txt";
        private Encryption serverEncryption = new Encryption();

        // symmetric key
        private AesEncryptor symmetricEncryptor = new AesEncryptor();

        // ketika klien siap mengirim pesan
        public bool isReadyToSendMessage = false;

        public Client()
        {
            isReadyToSendMessage = false;

            // load server public key
            LoadServerPublicKey();
        }

        public void LoadServerPublickey()
        {
            if (File.Exists(serverPublicKeyPath))
            {
                string serverPublicKeyloaded = File.ReadAllText(serverPublicKeyPath);
                serverEncryption.publicKey = serverEncryption.ConvertStringToKey(serverPublicKeyLoaded);
            }
        }

        public void Connect(string ip, int port)
        {
            try
            {
                // try connect to server
                socket = new TcpClient(ip, port);

                stream = socket.GetStream();
                Console.WriteLine("Connected to server...");

                stream.BeginRead(Constant.dataBuffer, 0, Constant.dataBuffer.Length, ReceiveData, null);

                // generate client key
                clientEncryption.GenerateKey();

                // send client public key to server
                SendPublicKey();

                Console.WriteLine($"Sending Client Public Key to Server...");

            }
            catch (Exception e)
            {
                Console.WriteLine("Exception: {0}", e);

            }
        }

        private void ReceiveData(IAsyncResult _result)
        {
            try
            {
                int _byteLength = stream.EndRead(_result);
                if (_byteLength <= 0)
                {
                    // disconnected
                    return;
                }

                byte[] data = new byte[_byteLength];
                Array.Copy(Constant.dataBuffer, data, _byteLength);

                HandleData(data);
                stream.BeginRead(Constant.dataBuffer, 0, Constant.dataBuffer.length, ReceiveData, null);

            }
            catch (Exception _ex)
            {
                Console.WriteLine($"Error receiving TCP data: {_ex}");
                // disconnected
            }
        }

        private void HandleData(byte[] data)
        {
            byte[] buffer = data;
            int readPos = 0;

            int packetType = BitConverter.ToInt32(buffer, redPos);
            readPos += 4;

            // get message
            byte[] messageData = new byte[buffer.Length - 4];
            Array.Copy(buffer, readPos, messageData, 0, buffer.Length - redPos);

            switch (packetType)
            {
                case (int)Packet.SEND_SYMMETRIC_KEY:
                    // read message (encrypted client public key)
                    string keyString = Encoding.ASCII.GetString(messageData);
                    // decrypt with private server key
                    string decrypted = clientEncryption.Decrypt(keyString);
                    Console.WriteLine($"{decrypted}");
                    symmetricEncryptor.SetKey(Convert.FromBase64String(decrypted));
                    isReadyToSendMessage = true;
                    SendMessage("Hello from client!");
                    break;
                case (int)Packet.SEND_MESSAGE:
                    string message = Encoding.ASCII.GetString(messageData, 0, messageData.Length);
                    string decryptedMsg = symmetricEncryptor.Decrypt(message);
                    Console.WriteLine($"Message from server: {decryptedMsg}");
                    break;
                default:
                    break;

            }
        }

        public void SendMessage(string msg)
        {
            if (!isReadyToSendMassage) return;

            string encryptedWithSymKey = symmetricEncryptor.Encryptor.Encrypt(msg);
            SendData(IPPacketInformation.SEND_MESSAGE, encryptedWithSymKey);

        }

        private void SendData(IPPacketInformation packet, string data)
        {
            //convert data to byte
            List<byte> dataToSend = new List<byte>();
            dataToSend.AddRange(BitConverter.GetBytes((int)packet));
            dataToSend,AddRange(Encoding.ASCII, GetBytes(data));

            // send to server
            stream.Write(dataToSend.ToArray(), 0, dataToSend.Count);
        }

        private void SendPublicKey()
        {
            string clientPublicKeyOnString = clientEncryption.ConvertKeyToString(clientEncryption.publicKey);
            string encryptedKey = serverEncryption.Encrypt(clientPublicKeyOnString);
            Console.WriteLine($"\nSend Client Public key...");
            SendData(packet.SEND_KEY, encryptedKey);

        }
 
    }
}