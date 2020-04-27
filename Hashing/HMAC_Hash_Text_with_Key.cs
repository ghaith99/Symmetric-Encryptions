using System;
using System.IO;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

public class Program
{
	public enum EncryptionEncoding
	{
		Default,
		ANSI,
		Unicode,
		BigEndianUnicode,
		UTF8
	}

	public enum KeyedHashAlgorithmForAction
	{
		HMACMD5,
		HMACRIPEMD160,
		HMACSHA1,
		HMACSHA256,
		HMACSHA384,
		HMACSHA512,
		MACTripleDES
	}

	public static Dictionary<EncryptionEncoding, Encoding> EncodingMapping;
	public static void Main()
	{
		MapEncryptionEncodingEnums();
		String textToHash = @"HMAC Hash with Key";
        String hashKey = @"12345";
		String hashedText = "";
		HashTextWithKey(textToHash, ref hashedText, keyedHashAlgorithm: (int)KeyedHashAlgorithmForAction.HMACMD5, encoding: (int)EncryptionEncoding.UTF8, hashKey: hashKey);
		Console.WriteLine(hashedText);
	}

	public static void HashTextWithKey(String textToHash, ref String hashedText, int keyedHashAlgorithm, int encoding, string hashKey)
	{
		try
		{
			Encoding encoding2 = EncodingMapping[(EncryptionEncoding)encoding];
			byte[] bytes = encoding2.GetBytes(textToHash);
			byte[] bytes2 = encoding2.GetBytes(hashKey);
			byte[] inArray = HashDataWithKeyImp((KeyedHashAlgorithmForAction)keyedHashAlgorithm, bytes, bytes2);
			if (hashedText != null)
			{
				hashedText = Convert.ToBase64String(inArray);
			}
		}
		catch (Exception ex)
		{
			Console.WriteLine(ex);
		}
	}

	private static byte[] HashDataWithKeyImp(KeyedHashAlgorithmForAction keyedHashAlgorithmSafe, byte[] dataBytes, byte[] keyBytes)
	{
		byte[] result;
		using (KeyedHashAlgorithm keyedHashAlgorithm = GetKeyedHashAlgorithm(keyedHashAlgorithmSafe))
		{
			keyedHashAlgorithm.Key = keyBytes;
			result = keyedHashAlgorithm.ComputeHash(dataBytes);
			keyedHashAlgorithm.Clear();
		}

		return result;
	}

	//Helpers
	private static KeyedHashAlgorithm GetKeyedHashAlgorithm(KeyedHashAlgorithmForAction keyedHashAlgorithm)
	{
		switch (keyedHashAlgorithm)
		{
			case KeyedHashAlgorithmForAction.HMACMD5:
				return new HMACMD5();
			case KeyedHashAlgorithmForAction.HMACRIPEMD160:
				return new HMACRIPEMD160();
			case KeyedHashAlgorithmForAction.HMACSHA1:
				return new HMACSHA1();
			case KeyedHashAlgorithmForAction.HMACSHA256:
				return new HMACSHA256();
			case KeyedHashAlgorithmForAction.HMACSHA384:
				return new HMACSHA384();
			case KeyedHashAlgorithmForAction.HMACSHA512:
				return new HMACSHA512();
			case KeyedHashAlgorithmForAction.MACTripleDES:
				return new MACTripleDES();
			default:
				throw new InvalidOperationException();
		}
	}

	public static void MapEncryptionEncodingEnums()
	{
		//mapping to enum values as the Encoding are not enums (ex.Encoding.Default is a function)
		EncodingMapping = new Dictionary<EncryptionEncoding, Encoding>();
		EncodingMapping[EncryptionEncoding.Default] = Encoding.Default;
		EncodingMapping[EncryptionEncoding.ANSI] = Encoding.ASCII;
		EncodingMapping[EncryptionEncoding.Unicode] = Encoding.Unicode;
		EncodingMapping[EncryptionEncoding.BigEndianUnicode] = Encoding.BigEndianUnicode;
		EncodingMapping[EncryptionEncoding.UTF8] = Encoding.UTF8;
	}
}