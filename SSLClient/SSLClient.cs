using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SSLClient
{
    class SSLClient
    {
        #region static variables
        public static string delimeter = "748159263";

        public static string clientNonce;

        public static string chosenSecret;

        public static string Kstring;

        public static byte[] totalMessages = new byte[0];
        #endregion

        #region main method

        static void Main(string[] args)
        {
            generateRandoms(16, 16);
            // send our nonce to the server and get the servers response
            Console.WriteLine("1. Client is sending nonce to server:\nNonce\t> " + pp(clientNonce) +  "\n");
            string serverResponse = sendMessage("nonce" + delimeter + clientNonce, 11000);
            Console.Write("2. Client recieves nonce and ssl certificate from server:\nNonce\t> ");
            // split the server response on our delimeter
            string[] serverResponseSplit = serverResponse.Split(new string[]{delimeter}, StringSplitOptions.None);
            // the first item is the cert from the server
            string serverCertificate = serverResponseSplit[0];
            // the second item is the server nonce
            string serverNonce = serverResponseSplit[1];

            Console.WriteLine(pp(serverNonce) + "\n");

            // add all the messages we have seen so far to our total messages that we can later hash them
            totalMessages = combineBytes(totalMessages, getBytes(clientNonce));
            totalMessages = combineBytes(totalMessages, getBytes(serverCertificate));
            totalMessages = combineBytes(totalMessages, getBytes(serverNonce));

            // calculate all the necessary incoming and outgoing keys from the two nonces
            Console.WriteLine("3. Client chooses Secret S, and computes all other keys");
            byte[] K = xorBytes(getBytes(serverNonce), xorBytes(getBytes(clientNonce), getBytes(chosenSecret)));
            byte[] IntegrityProtectionKeyCient = transform(K, -1);
            byte[] IntegrityProtectionKeyServer = transform(K, 1);
            byte[] EncryptionKeyCient = transform(K, -2);
            byte[] EncryptionKeyServer = transform(K, 2);
            Kstring = getString(K);

            Console.WriteLine("S>\t" + pp(chosenSecret));
            Console.WriteLine("K>\t" + pp(K));
            Console.WriteLine("IPKeyClient>\t" + pp(IntegrityProtectionKeyCient));
            Console.WriteLine("IPKeyServer>\t" + pp(IntegrityProtectionKeyServer));
            Console.WriteLine("EncryptionKeyClient>\t" + pp(EncryptionKeyCient));
            Console.WriteLine("EncryptionKeyServer>\t" + pp(EncryptionKeyServer) + "\n");

            // encrypt the chosen secret with the servers certificate
            Console.WriteLine("4. Client encrypts secret using public key found in certificate");
            string RsaEncryptedSecret = rsaEncrypt(chosenSecret, serverCertificate);
            Console.WriteLine("encrypted secret>\t", pp(RsaEncryptedSecret) + "\n");
            
            // add this message to our total messages
            totalMessages = combineBytes(totalMessages, getBytes(RsaEncryptedSecret));

            // send the encrypted secret to the server, and get the hash of messages as a response
            Console.WriteLine("5. Client sends encrypted secret to server");
            string hashOfMessagesFromServer = sendMessage("secret" + delimeter + RsaEncryptedSecret, 11001);
            Console.WriteLine("6. Client recieves hash of all messages from server\nhash>\t" + pp(hashOfMessagesFromServer) + "\n");

            // calculate our own hash of messages and make sure they are equivalent
            Console.WriteLine("7. Client compares hash of all messages from server, to its own calculated hash");
            if(getString(getHashOfMessages("server")) != hashOfMessagesFromServer)
            {
                Console.WriteLine("server hash does not match out own!");
                Console.Read();
                return;
            }
            Console.WriteLine("8. Hash comparison PASSED");

            // send our own hash of messages to the server so the server can verify; get the data message as a response
            Console.WriteLine("9. Client sends computed hash of messages to server\nhash>\t" + pp(getHashOfMessages("client") + "\n"));
            string dataMessage = sendMessage("hash" + delimeter + getString(getHashOfMessages("client")), 11002);
            Console.WriteLine("10. Client recieves data message from server");

            // verify the data message to be the correct file
            Console.WriteLine("11. Client attempts to verify data");
            if(!verifyDataMessage(dataMessage, IntegrityProtectionKeyServer, EncryptionKeyServer))
            {
                Console.WriteLine("data does not verify!!! PANIC!!!");
            }
            Console.WriteLine("12. data verification and hash match have PASSED");

            Console.WriteLine("");
            Console.WriteLine("DONE");
            Console.WriteLine("Press Enter To Terminate");
            Console.Read();
        }

        public static string pp(string toPrint)
        {
            return BitConverter.ToString(getBytes(toPrint));
        }

        public static string pp(byte[] toPrint)
        {
            return BitConverter.ToString(toPrint);
        }

        #endregion

        #region data message verification

        /// <summary>
        /// verify
        /// </summary>
        /// <param name="message"></param>
        /// <param name="integrityProtectionKey"></param>
        /// <param name="encryptionKey"></param>
        /// <returns></returns>
        public static bool verifyDataMessage(string message, byte[] integrityProtectionKey, byte[] encryptionKey)
        {
            // split message on delim
            string[] messageSplits = message.Split(new string[] { delimeter }, StringSplitOptions.None);

            // get sequence
            string sequence = messageSplits[0];
            Console.WriteLine("sequence>\t" + pp(sequence));

            // get RH
            string recordHeader = messageSplits[1];
            Console.WriteLine("record header>\t" + pp(recordHeader));

            // get encrypted portion
            string encryptedPortion = messageSplits[2];

            // decrypt the encryption
            string decryptedMessage = Decrypt(encryptedPortion, encryptionKey);

            // split the decrypted message on delim
            string[] decryptedSplits = decryptedMessage.Split(new string[] { delimeter }, StringSplitOptions.None);

            // get dataFile
            string dataFile = decryptedSplits[0];

            // get the hash
            string serverHash = decryptedSplits[1];
            Console.WriteLine("hash>\t" + pp(serverHash));

            // compute our own hash
            string clientHash = getString(getHashOfMessage(
                getBytes(sequence + delimeter + recordHeader + delimeter + dataFile), getString(integrityProtectionKey)));

            // verify the matching hash
            if(serverHash != clientHash)
            {
                return false;
            }

            // get client data file
            string clientDataFile = loadFile();

            // verify the file contents
            if(clientDataFile != dataFile)
            {
                return false;
            }

            // if we made it here,
            return true;
        }

        /// <summary>
        /// load the testFile into a string
        /// </summary>
        /// <returns></returns>
        public static string loadFile()
        {
            return File.ReadAllText("testFile.txt");
        }

        #endregion

        #region message sending
        /// <summary>
        /// send a message on localhost on the given port
        /// </summary>
        /// <param name="toSend"></param>
        /// <param name="port"></param>
        /// <returns></returns>
        public static string sendMessage(string toSend, int port)
        {
            // Data buffer for incoming data.
            byte[] bytes = new byte[131072];

            string result = null;

            // Connect to a remote device.
            try
            {
                IPAddress ipAddress = IPAddress.Loopback;
                IPEndPoint remoteEP = new IPEndPoint(ipAddress, port);

                // Create a TCP/IP  socket.
                Socket sender = new Socket(AddressFamily.InterNetwork,
                    SocketType.Stream, ProtocolType.Tcp);

                sender.Connect(remoteEP);
                // Encode the data string into a byte array.
                byte[] msg = getBytes(toSend + "<EOF>");

                // Send the data through the socket.
                int bytesSent = sender.Send(msg);

                // Receive the response from the remote device.
                int bytesRec = sender.Receive(bytes);

                //result = Encoding.ASCII.GetString(bytes, 0, bytesRec);
                result = getString(bytes);
                result = result.Substring(0, result.IndexOf("<EOF>"));
                // Release the socket.
                sender.Shutdown(SocketShutdown.Both);
                sender.Close();

            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }
            return result;
        }
        #endregion

        #region encryption and hashing
        /// <summary>
        /// generates our needed cryptographically strong bytes for this scenario
        /// </summary>
        /// <param name="numberOfNonceBytes"></param>
        /// <param name="numberOfChosenSecretBytes"></param>
        public static void generateRandoms(int numberOfNonceBytes, int numberOfChosenSecretBytes)
        {
            RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
            byte[] randomNonceBytes = new byte[numberOfNonceBytes];
            byte[] randomChosenSecretBytes = new byte[numberOfChosenSecretBytes];

            rngCsp.GetNonZeroBytes(randomNonceBytes);
            rngCsp.GetNonZeroBytes(randomChosenSecretBytes);

            clientNonce = getString(randomNonceBytes);
            chosenSecret = getString(randomChosenSecretBytes);
        }

        /// <summary>
        /// encrypt the given message with the given publik key inside of the certificate
        /// </summary>
        /// <param name="message"></param>
        /// <param name="certificateString"></param>
        /// <returns></returns>
        public static string rsaEncrypt(string message, string certificateString)
        {
            //var newCert = new X509Certificate2(getBytes(certificateString));
            //var clientRSA = (RSACryptoServiceProvider)newCert.PublicKey.Key;

            var clientRSA = new RSACryptoServiceProvider();
            clientRSA.FromXmlString(certificateString);

            // converto to bytes
            var bytesPlainTextData = getBytes(message);

            //apply pkcs#1.5 padding and encrypt our data 
            var bytesCipherText = clientRSA.Encrypt(bytesPlainTextData, false);

            // convert back to a string
            var cipherText = getString(bytesCipherText);

            return cipherText;
        }

        /// <summary>
        /// get the hash value of all messages so far
        /// </summary>
        /// <returns></returns>
        public static byte[] getHashOfMessage(byte[] totalMessages, string appendage)
        {
            MD5 md5 = System.Security.Cryptography.MD5.Create();
            byte[] inputBytes = combineBytes(getBytes(Kstring), totalMessages);
            inputBytes = combineBytes(inputBytes, getBytes(appendage));
            byte[] hash = md5.ComputeHash(inputBytes);
            return md5.ComputeHash(inputBytes);
        }

        /// <summary>
        /// triple DES decryptor
        /// </summary>
        /// <param name="cipherBlock"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static string Decrypt(string cipherBlock, byte[] key)
        {
            byte[] IV = new byte[] { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7 };
            byte[] toEncryptArray = getBytes(cipherBlock);

            // Set the secret key for the tripleDES algorithm
            TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
            tdes.Key = key;
            tdes.IV = IV;
            tdes.Mode = CipherMode.CBC;
            tdes.Padding = PaddingMode.PKCS7;

            ICryptoTransform cTransform = tdes.CreateDecryptor();
            byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
            tdes.Clear();

            // Return the Clear decrypted TEXT
            return getString(resultArray);
        }

        /// <summary>
        /// get the hash value of all messages so far
        /// </summary>
        /// <returns></returns>
        public static byte[] getHashOfMessages(string appendage)
        {
            MD5 md5 = System.Security.Cryptography.MD5.Create();
            byte[] inputBytes = combineBytes(getBytes(Kstring), totalMessages);
            inputBytes = combineBytes(inputBytes, getBytes(appendage));
            byte[] hash = md5.ComputeHash(inputBytes);
            return md5.ComputeHash(inputBytes);
        }
        #endregion

        #region string byte methods
        /// <summary>
        /// xor two byte arrays together
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        /// <returns></returns>
        public static byte[] xorBytes(byte[] a, byte[] b)
        {
            byte[] toReturn = new byte[a.Length];
            for(int i = 0; i < a.Length; i++)
            {
                toReturn[i] = (byte)(a[i] ^ b[i]);
            }
            return toReturn;
        }

        /// <summary>
        /// get a string from bytes
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static string getString(byte[] bytes)
        {
            char[] chars = new char[bytes.Length / sizeof(char)];
            System.Buffer.BlockCopy(bytes, 0, chars, 0, bytes.Length);
            return new string(chars);
        }

        /// <summary>
        /// get a byte[] from a string
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public static byte[] getBytes(string str)
        {
            byte[] bytes = new byte[str.Length * sizeof(char)];
            System.Buffer.BlockCopy(str.ToCharArray(), 0, bytes, 0, bytes.Length);
            return bytes;
        }

        /// <summary>
        /// transform the given byte[] by the value amount
        /// </summary>
        /// <param name="toSub"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public static byte[] transform(byte[] toSub, int value)
        {
            toSub[toSub.Length-1] = (byte)(toSub[toSub.Length-1] + value);
            return toSub;
        }

        /// <summary>
        /// combine two byte []'s
        /// </summary>
        /// <param name="a1"></param>
        /// <param name="a2"></param>
        /// <returns></returns>
        public static byte[] combineBytes(byte[] a1, byte[] a2)
        {
            byte[] rv = new byte[a1.Length + a2.Length];
            System.Buffer.BlockCopy(a1, 0, rv, 0, a1.Length);
            System.Buffer.BlockCopy(a2, 0, rv, a1.Length, a2.Length);
            return rv;
        }
        #endregion
    }
}
