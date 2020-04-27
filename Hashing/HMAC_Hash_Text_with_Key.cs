using System;
using System.IO;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

public class Program
{

    public enum EncryptionEncoding{Default, ANSI, Unicode, BigEndianUnicode, UTF8}
	public enum KeyedHashAlgorithmForAction { HMACMD5, HMACRIPEMD160, HMACSHA1, HMACSHA256, HMACSHA384, HMACSHA512, MACTripleDES }
	public static Dictionary<EncryptionEncoding, Encoding> EncodingMapping;

	public static void Main()
	{
        MapEncryptionEncodingEnums();
		
       
        String textToHash=@"HMAC Hash with Key";
        String hashedText="";
        HashTextWithKey(textToHash,iParam1,ref hashedText,keyedHashAlgorithm:(int)KeyedHashAlgorithmForAction.HMACMD5,encoding:(int)EncryptionEncoding.UTF8, hashKey:@"12345");
		Console.WriteLine(hashedText);	
	}


	public static void HashTextWithKey(Variant textToHash, ref Variant hashedText, int keyedHashAlgorithm, int encoding, string hashKey)
		{
			try
			{
				Encoding encoding2 = EncodingMapping[(EncryptionEncoding)encoding];
				byte[] bytes = encoding2.GetBytes(textToHash);
				byte[] bytes2 = encoding2.GetBytes(hashKey);
				byte[] inArray = HashDataWithKeyImp((KeyedHashAlgorithmForAction)keyedHashAlgorithm, bytes, bytes2);
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


//Helpers

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