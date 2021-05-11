using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Encryption;

namespace DiffieHellmanExample
{
	/// <summary>
	/// Example showing how to use diffie hellman to exchange a shared secret
	/// using a certificate to validate the authenticity of the server public key
	/// and using the shared secret to send an encrypted message
	/// </summary>
	class Program
	{
		private static Client Client;
		private static Server Server;


		static void Main(string[] args)
		{
			Server = new Server();
			Client = new Client();

			EstablishSharedSecret();
			ExchangeSecretMessageTest();
		}

		/// <summary>
		/// Establishes a shared secret through a Diffie Hellman key exchange.
		/// The shared server public key is verified through a certificate file by the client to prevent man-in-the-middle-attacks 
		/// </summary>
		private static void EstablishSharedSecret()
		{
			var serverMessage = Server.GenerateKeyExchangeMessage();
			var clientPublicKey = Client.OnHail(serverMessage.serverPublicKey, serverMessage.signedKey);
			Server.OnHailResponse(clientPublicKey);
		}
		
		/// <summary>
		/// Using the shared secret, a message is created by the server that can be read by the client
		/// The initialization vector for AES encryption is sent along with the message (unencrypted prepending the actual message)
		/// </summary>
		private static void ExchangeSecretMessageTest()
		{
			var encryptedMessage = Server.GenerateSecretMessage("Hello World!");
			Console.WriteLine($"Encrypted byte message: {Convert.ToBase64String(encryptedMessage)}");

			var message = Client.DecryptMessage(encryptedMessage);
			Console.WriteLine($"Decrypted message: {message}");
		}
	}

	public class Server
	{
		private const string PrivateKeyCertPath = "data/ca-trusted.pfx";
		private const string PrivateKeyPassword = "password123";
		private X509Certificate2 privateCert;
		private ECDiffieHellmanCng diffieHellman;
		private byte[] sharedSecret;

		public Server()
		{
			LoadCert();
			PrepareDiffieHellman();
		}

		public void LoadCert()
		{
			var certBytes = File.ReadAllBytes(PrivateKeyCertPath);
			privateCert = new X509Certificate2(certBytes, PrivateKeyPassword);
		}

		public void PrepareDiffieHellman()
		{
			diffieHellman = new ECDiffieHellmanCng();
			diffieHellman.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
			diffieHellman.HashAlgorithm = CngAlgorithm.Sha256;
		}

		public (byte[] serverPublicKey, byte[] signedKey) GenerateKeyExchangeMessage()
		{
			var publicKey = diffieHellman.PublicKey.ToByteArray();
			var csp = (RSACng) privateCert.PrivateKey;
			var signedKey = csp.SignData(publicKey, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);

			return (publicKey, signedKey);
		}

		public void OnHailResponse(byte[] clientPublicKeyBlob)
		{
			var serverKey = ECDiffieHellmanCngPublicKey.FromByteArray(clientPublicKeyBlob, CngKeyBlobFormat.EccPublicBlob);
			sharedSecret = diffieHellman.DeriveKeyMaterial(serverKey);
		}

		public byte[] GenerateSecretMessage(string message)
		{
			var byteMessage = Encoding.UTF8.GetBytes(message);
			return EncryptionHelper.SimpleEncrypt(byteMessage, sharedSecret);
		}
	}
	
	public class Client
	{
		private const string PublicCertPath = "data/ca-trusted.cer";
		
		private X509Certificate2 publicCert;
		private ECDiffieHellmanCng diffieHellman;
		private byte[] sharedSecret;

		public Client()
		{
			LoadCert();
			PrepareDiffieHellman();
		}
		
		public void LoadCert()
		{
			var certBytes = File.ReadAllBytes(PublicCertPath);
			publicCert = new X509Certificate2(certBytes);
		}

		public void PrepareDiffieHellman()
		{
			diffieHellman = new ECDiffieHellmanCng();
			diffieHellman.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
			diffieHellman.HashAlgorithm = CngAlgorithm.Sha256;
		}

		public byte[] OnHail(byte[] serverPublicKeyBlob, byte[] serverSignedKey)
		{
			var csp = (RSACng) publicCert.PublicKey.Key;
			var validKey = csp.VerifyData(serverPublicKeyBlob, serverSignedKey, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);

			if (!validKey)
			{
				throw new Exception("Invalid key signature for server key! This was not signed with the certificate, the client trusts in.");
			}

			var serverKey = ECDiffieHellmanCngPublicKey.FromByteArray(serverPublicKeyBlob, CngKeyBlobFormat.EccPublicBlob);
			sharedSecret = diffieHellman.DeriveKeyMaterial(serverKey);
			return diffieHellman.PublicKey.ToByteArray();
		}

		public string DecryptMessage(byte[] secretMessage)
		{
			var bytes = EncryptionHelper.SimpleDecrypt(secretMessage, sharedSecret);
			return Encoding.UTF8.GetString(bytes);
		}
	}
}