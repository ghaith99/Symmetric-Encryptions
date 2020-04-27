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
		
        
        
String iParam0= @"C:\Users\pc\Desktop\Dlvr.txt";
String iParam1=null;
String oParam0="";
HashFileWithKey( iParam0,iParam1,ref oParam0,0,2,true,@"e34b5a0d67d948b9e300208aa47d9770");

		Console.WriteLine(hashedText);
	}

public static void HashFileWithKey(String fileToHash, ref String hashedText, int keyedHashAlgorithm, int encoding, string hashKey)
		{
            FileInfo fileVariant = new FileInfo(fileToHash);
			try
			{
				if (!fileVariant.Exists)
				{
					throw new ActionException(1, string.Format("File {0} does not exist", fileVariant), null);
				}
				Encoding encoding2 = EncodingMapping[(EncryptionEncoding)encoding];
				byte[] dataBytes = ReadFileBytes(fileVariant.FullName, encoding2);
				byte[] bytes = encoding2.GetBytes(hashKey);
				byte[] inArray = HashDataWithKeyImp((KeyedHashAlgorithmForAction)keyedHashAlgorithm, dataBytes, bytes);
				if (hashedText != null)
				{
					hashedText = new TextVariant(Convert.ToBase64String(inArray));
				}
			}
			catch (Exception ex)
			{
                Console.WriteLine(ex);
			}
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