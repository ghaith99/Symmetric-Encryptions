using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

public class Program
{

    public enum EncryptionEncoding{Default, ANSI, Unicode, BigEndianUnicode, UTF8}
	public enum HashAlgorithmForAction { MD5, RIPEMD160, SHA1, SHA256, SHA384, SHA512 }
	public static Dictionary<EncryptionEncoding, Encoding> EncodingMapping;

	public static void Main()
	{
        MapEncryptionEncodingEnums();
		
        String textToHash= "Hello World";
        String hashedText= "";
        HashText( textToHash,ref hashedText, hashAlgorithm: 0, encoding: (int)EncryptionEncoding.UTF8);

		Console.WriteLine(hashedText);	
		
	}



    public static void HashText(String textToHash, ref String hashedText, int hashAlgorithm, int encoding)
    {
        try
        {
            byte[] bytes = EncodingMapping[(EncryptionEncoding)encoding].GetBytes(textToHash);
            byte[] inArray = HashDataImp((HashAlgorithmForAction)hashAlgorithm, bytes);
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

	private static byte[] HashDataImp(HashAlgorithmForAction hashAlgorithm, byte[] dataBytes)
		{
			byte[] result;
			using (HashAlgorithm hashAlgorithm2 = GetHashAlgorithm(hashAlgorithm))
			{
				result = hashAlgorithm2.ComputeHash(dataBytes);
				hashAlgorithm2.Clear();
			}
			return result;
		}

//Helpers
		private static HashAlgorithm GetHashAlgorithm(HashAlgorithmForAction hashAlgorithm)
		{
			switch (hashAlgorithm)
			{
			case HashAlgorithmForAction.MD5:
				return new MD5Cng();
			case HashAlgorithmForAction.RIPEMD160:
				return new RIPEMD160Managed();
			case HashAlgorithmForAction.SHA1:
				return new SHA1Cng();
			case HashAlgorithmForAction.SHA256:
				return new SHA256Cng();
			case HashAlgorithmForAction.SHA384:
				return new SHA384Cng();
			case HashAlgorithmForAction.SHA512:
				return new SHA512Cng();
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