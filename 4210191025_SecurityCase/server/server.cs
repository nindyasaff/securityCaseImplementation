using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using packetData;

namespace server
{
    class server
    {
        TcpListener listener;
        private string ip;
        private int port;
        private List<Client> clientOnServer = new List<Client>();

        private Encryption serverEncryption = new Encryption();
        private string serverPrivateKeyPath = Directory.GetCurrentDirectory() + "\\server-private-key.txt";
        private string serverPublicKeyPath = Directory.GetCurrentDirectory() + "\\server-public-key.txt";

        public Server(string _ip, int _port)
        {
            ip = _ip;
            port = _port;

            LoadServerKey();
        }

        public void LoadServerKey()
        {
            if (File.Exists(serverPublicKeyPath) && File.Exists(serverPrivateKeyPath))
            {
                // load private key
                string privateKeyLoaded = File.ReadAllText(serverPrivateKeyPath);
                serverEncryption.privateKey = serverEncryption.ConvertStringToKey(privateKeyLoaded);

                // load public key
                string publicKeyLoaded = File.ReadAllText(serverPublicKeyPath);
                serverEncryption.publicKey = serverEncryption.ConvertStringToKey(publicKeyLoaded);
            }
            else
            {
                // generate public and private key
                serverEncryption.GenerateKey();

                // save key to file
                File.WriteAllText(serverPrivateKeyPath, serverEncryption.ConvertKeyToString(serverEncryption.privateKey));
                File.WriteAllText(serverPublicKeyPath, serverEncryption.ConvertKeyToString(serverEncryption.publicKey));
            }


        }

        public void Start()
        {
            listener = new TcpListener(IPAddress.Parse(ip), port);
            listener.Start();
            Console.WriteLine("Server Started..");
            listener.BeginAcceptTcpClient(ConnectionCallback, null);
        }

        private void ConnectionCallback(IAsyncResult _result)
        {
            TcpClient client = listener.EndAcceptTcpClient(_result);
            Console.WriteLine($"Incoming connection from {client.Client.RemoteEndPoint}...");
            listener.BeginAcceptTcpClient(ConnectionCallback, null);

            // add player on server
            Client newPlayer = new Client(client, serverEncryption);
            clientOnServer.Add(newPlayer);
        }
    }

    public class Client
    {
        private TcpClient socket;
        private NetworkStream stream;
        private Encryption clientEncryption = new Encryption();
        private Encryption serverEncryption = new Encryption();
        private AesEncryptor symmetricEncryptor = new AesEncryptor();

        public Client(TcpClient _client, Encryption serverEncryption)
        {
            this.serverEncryption = serverEncryption;

            socket = _client;
            socket.ReceiveBufferSize = Constant.dataBuffer.Length;
            socket.SendBufferSize = Constant.dataBuffer.Length;

            stream = socket.GetStream();

            stream.BeginRead(Constant.dataBuffer, 0, Constant.dataBuffer.Length, ReceiveData, null);
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
                Console.WriteLine($"Client disconnected..");

                // disconnected
                socket.Close();
            }
        }

        private void HandleData(byte[] data)
        {
            byte[] buffer = data;
            int readPos = 0;

            // read packet type
            int packetType = BitConverter.ToInt32(buffer, readPos);
            readPos += 4;

            // get message
            byte[] messageData = new byte[buffer.Length - 4];
            Array.Copy(buffer, readPos, messageData, 0, buffer.Length - readPos);

            switch (packetType)
            {
                case (int)Packet.SEND_KEY:
                    // read message (encrypted client public key)
                    string keyString = Encoding.ASCII.GetString(messageData);
                    // decrypt with private server key
                    string decrypted = serverEncryption.Decrypt(keyString);
                    Console.WriteLine($"Received Client Public Key..");
                    // convert string to client public key
                    clientEncryption.publicKey = serverEncryption.ConvertStringToKey(decrypted);
                    SendSymmetricKey();
                    break;
                case (int)Packet.SEND_MESSAGE:
                    try
                    {
                        string message = Encoding.ASCII.GetString(messageData, 0, messageData.Length);
                        string decryptedMsg = symmetricEncryptor.Decrypt(message);
                        Console.WriteLine($"Message from Client: {decryptedMsg}");
                        SendMessage("Hello from server!");
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"Error: {e.InnerException}");
                    }
                    break;
                default:
                    break;
            }

        }

        public void SendData(Packet packet, string data)
        {
            // convert data to byte
            List<byte> dataToSend = new List<byte>();
            dataToSend.AddRange(BitConverter.GetBytes((int)packet));
            dataToSend.AddRange(Encoding.ASCII.GetBytes(data));

            // send to server
            stream.Write(dataToSend.ToArray(), 0, dataToSend.Count);
        }

        public void SendData(Packet packet, byte[] data)
        {
            // convert data to byte
            List<byte> dataToSend = new List<byte>();
            dataToSend.AddRange(BitConverter.GetBytes((int)packet));
            dataToSend.AddRange(data);

            // send to server
            stream.Write(dataToSend.ToArray(), 0, dataToSend.Count);
        }

        public void SendMessage(string msg)
        {
            string encryptedWithSymKey = symmetricEncryptor.Encrypt(msg);
            SendData(Packet.SEND_MESSAGE, encryptedWithSymKey);
        }

        public void SendSymmetricKey()
        {
            symmetricEncryptor.GenerateNewKey();
            string key = Convert.ToBase64String(symmetricEncryptor.aes.Key);
            string encryptedKey = clientEncryption.Encrypt(key);
            SendData(Packet.SEND_SYMMETRIC_KEY, encryptedKey);
        }
    }
}