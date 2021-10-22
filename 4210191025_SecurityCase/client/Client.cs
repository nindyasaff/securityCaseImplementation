using PacketData;
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

        // when client ready to send message
        public bool isReadyToSendMessage = false;

        public Client()
        {
            isReadyToSendMessage = false;

            // load server public key
            LoadServerPublicKey();
        }

        public void LoadServerPublicKey()
        {
            if (File.Exists(serverPublicKeyPath))
            {
                string serverPublicKeyLoaded = File.ReadAllText(serverPublicKeyPath);
                serverEncryption.publicKey = serverEncryption.ConvertStringToKey(serverPublicKeyLoaded);
            }
      
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
                stream.BeginRead(Constant.dataBuffer, 0, Constant.dataBuffer.Length, ReceiveData, null);
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

            int packetType = BitConverter.ToInt32(buffer, readPos);
            readPos += 4;

            // get message
            byte[] messageData = new byte[buffer.Length - 4];
            Array.Copy(buffer, readPos, messageData, 0, buffer.Length - readPos);

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
