using System;
using System.IO;

					
public class Program
{
	public static void Main()
	{
		
        String textToHash=new TextString(@"""Hello Hash""");
        String hashedText=String.CreateString(_Variables["hashedtext"]);
        HashText( textToHash,ref hashedText, hashAlgorithm: 0, encoding: 2);

		Console.WriteLine(hashedText);	
		
	}

public static void HashText(Variant textToHash, ref Variant hashedText, int hashAlgorithm, int encoding)
{
	TextVariant textVariant = (TextVariant)ActionRuntimeBase.CheckType(textToHash, "Text to Hash", false, typeof(TextVariant));
	try
	{
		byte[] bytes = CryptographyActions.EncodingMapping[(EncryptionEncoding)encoding].GetBytes(textVariant.ToString(CultureInfo.InvariantCulture));
		byte[] inArray = CryptographyActions.HashDataImp((HashAlgorithmForAction)hashAlgorithm, bytes);
		if (hashedText != null)
		{
			hashedText = new TextVariant(Convert.ToBase64String(inArray));
		}
	}
	catch (Exception ex)
	{
		if (ex is IWARuntimeActionException)
		{
			throw;
		}
		throw new ActionException(1, "Failed to hash text", ex);
	}
}

}