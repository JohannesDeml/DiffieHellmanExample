/*
 * This work (Modern Encryption of a String C#, by James Tuley), 
 * identified by James Tuley, is free of known copyright restrictions.
 * https://gist.github.com/4336842
 * http://creativecommons.org/publicdomain/mark/1.0/
 * Modified by Johannes Deml - Remove HMAC for this example
 */

using System;
using System.IO;
using System.Security.Cryptography;

namespace Encryption
{
	public static class EncryptionHelper
	{
		private static readonly RandomNumberGenerator Random = RandomNumberGenerator.Create();

		//Preconfigured Encryption Parameters
		public static readonly int BlockBitSize = 128;
		public static readonly int KeyBitSize = 256;

		/// <summary>
		/// Helper that generates a random key on each call.
		/// </summary>
		/// <returns></returns>
		public static byte[] NewKey()
		{
			var key = new byte[KeyBitSize / 8];
			Random.GetBytes(key);
			return key;
		}

		/// <summary>
		/// Simple Encryption(AES) then Authentication (HMAC) for a UTF8 Message.
		/// </summary>
		/// <param name="secretMessage">The secret message.</param>
		/// <param name="cryptKey">The crypt key.</param>
		/// <param name="nonSecretPayload">(Optional) Non-Secret Payload.</param>
		/// <returns>
		/// Encrypted Message
		/// </returns>
		/// <remarks>
		/// Adds overhead of (Optional-Payload + BlockSize(16) + Message-Padded-To-Blocksize +  HMac-Tag(32)) * 1.33 Base64
		/// </remarks>
		public static byte[] SimpleEncrypt(byte[] secretMessage, byte[] cryptKey, byte[] nonSecretPayload = null)
		{
			//User Error Checks
			if (cryptKey == null || cryptKey.Length != KeyBitSize / 8)
				throw new ArgumentException(String.Format("Key needs to be {0} bit!", KeyBitSize), "cryptKey");

			if (secretMessage == null || secretMessage.Length < 1)
				throw new ArgumentException("Secret Message Required!", "secretMessage");

			//non-secret payload optional
			nonSecretPayload = nonSecretPayload ?? new byte[] { };

			byte[] cipherText;
			byte[] iv;

			using (var aes = new AesManaged
			{
				KeySize = KeyBitSize,
				BlockSize = BlockBitSize,
				Mode = CipherMode.CBC,
				Padding = PaddingMode.PKCS7
			})
			{
				//Use random IV
				aes.GenerateIV();
				iv = aes.IV;

				using (var encrypter = aes.CreateEncryptor(cryptKey, iv))
				using (var cipherStream = new MemoryStream())
				{
					using (var cryptoStream = new CryptoStream(cipherStream, encrypter, CryptoStreamMode.Write))
					using (var binaryWriter = new BinaryWriter(cryptoStream))
					{
						//Encrypt Data
						binaryWriter.Write(secretMessage);
					}

					cipherText = cipherStream.ToArray();
				}
			}

			using (var messageStream = new MemoryStream())
			{
				using (var binaryWriter = new BinaryWriter(messageStream))
				{
					//Prepend non-secret payload if any
					binaryWriter.Write(nonSecretPayload);

					//Prepend IV
					binaryWriter.Write(iv);

					//Write Ciphertext
					binaryWriter.Write(cipherText);
				}

				return messageStream.ToArray();
			}
		}

		/// <summary>
		/// Simple Authentication (HMAC) then Decryption (AES) for a secrets UTF8 Message.
		/// </summary>
		/// <param name="encryptedMessage">The encrypted message.</param>
		/// <param name="cryptKey">The crypt key.</param>
		/// <param name="nonSecretPayloadLength">Length of the non secret payload.</param>
		/// <returns>Decrypted Message</returns>
		public static byte[] SimpleDecrypt(byte[] encryptedMessage, byte[] cryptKey, int nonSecretPayloadLength = 0)
		{
			//Basic Usage Error Checks
			if (cryptKey == null || cryptKey.Length != KeyBitSize / 8)
				throw new ArgumentException(String.Format("CryptKey needs to be {0} bit!", KeyBitSize), "cryptKey");

			if (encryptedMessage == null || encryptedMessage.Length == 0)
				throw new ArgumentException("Encrypted Message Required!", "encryptedMessage");

			var ivLength = (BlockBitSize / 8);

			//if message length is to small just return null
			if (encryptedMessage.Length < nonSecretPayloadLength + ivLength)
				return null;

			using (var aes = new AesManaged
			{
				KeySize = KeyBitSize,
				BlockSize = BlockBitSize,
				Mode = CipherMode.CBC,
				Padding = PaddingMode.PKCS7
			})
			{
				//Grab IV from message
				var iv = new byte[ivLength];
				Array.Copy(encryptedMessage, nonSecretPayloadLength, iv, 0, iv.Length);

				using (var decryptor = aes.CreateDecryptor(cryptKey, iv))
				using (var plainTextStream = new MemoryStream())
				{
					using (var decryptorStream = new CryptoStream(plainTextStream, decryptor, CryptoStreamMode.Write))
					using (var binaryWriter = new BinaryWriter(decryptorStream))
					{
						//Decrypt Cipher Text from Message
						binaryWriter.Write(
							encryptedMessage,
							nonSecretPayloadLength + iv.Length,
							encryptedMessage.Length - nonSecretPayloadLength - iv.Length
						);
					}

					//Return Plain Text
					return plainTextStream.ToArray();
				}
			}
		}
	}
}