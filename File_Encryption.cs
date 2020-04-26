


String fileToEncrypt="C:\Users\pc\Desktop\Dlvr.txt";
String varEncryptionKey=null;
String encryptedText="";
String salt=null;
String initializationVector=null;
EncryptFromFile( fileToEncrypt,varEncryptionKey,ref encryptedText,ref salt,ref initializationVector,encoding: 2,encryptionAlgorithm: 0,encryptionKey:"12345",blockSize:128,keySize:256,cipherMode:0,paddingMode:1,useSalt: false,useIv: false);
_Variables["encryptedtext"] = (String)encryptedText;


String iParam0= "";
String iParam1="C:\Users\pc\Desktop\decryptedFile.txt";
String iParam2=null;
String iParam3=null;
String iParam4=null;
String decryptedfile="String.CreateString(_Variables["decryptedfile"]);"
DecryptToFile( iParam0,iParam1,iParam2,iParam3,iParam4,ref oParam0,2,0,true,@"e34b5a0d67d948b9e300208aa47d9770",2,128,256,0,1,false,false);
_Variables["decryptedfile"] = (String)oParam0;



public static void EncryptFromFile(Variant fileToEncrypt, Variant varEncryptionKey, ref Variant encryptedText, ref Variant salt, ref Variant initializationVector, int encoding, int encryptionAlgorithm, string encryptionKey, int blockSize, int keySize, int cipherMode, int paddingMode, bool useSalt, bool useIv)
{
	FileVariant fileVariant = (FileVariant)ActionRuntimeBase.CheckType(fileToEncrypt, "File to Encrypt", false, typeof(FileVariant));
	TextVariant textVariant = encryptionKeyDirectly ? null : ((TextVariant)ActionRuntimeBase.CheckType(varEncryptionKey, "Encryption Key", false, typeof(TextVariant)));
	Encoding encoding2 = EncodingMapping[(EncryptionEncoding)encoding];
	CipherMode cipherMode2 = CipherModeMapping[(AlgorithmCipherMode)cipherMode];
	PaddingMode paddingMode2 = PaddingModeMapping[(AlgorithmPaddingMode)paddingMode];
	try
	{
		if (!fileVariant.Exists)
		{
			throw new ActionException(1, string.Format("File {0} does not exist", fileVariant), null);
		}
		byte[] dataBytes = ReadFileBytes(fileVariant.FullName.ToString(CultureInfo.InvariantCulture), encoding2);
		string key = encryptionKeyDirectly ? ActionRuntimeBase.SetText(encryptionKey) : textVariant.ToString(CultureInfo.InvariantCulture);
		System.ValueTuple<string, string, string> valueTuple = EncryptDataImp(encoding2, (SymmetricAlgorithmForAction)encryptionAlgorithm, blockSize, keySize, cipherMode2, paddingMode2, dataBytes, key, useSalt, useIv);
		if (encryptedText != null)
		{
			encryptedText = valueTuple.Item1;
		}
		if (salt != null)
		{
			salt = valueTuple.Item2;
		}
		if (initializationVector != null)
		{
			initializationVector = valueTuple.Item3;
		}
	}
	catch (Exception ex)
	{
		Console.WriteLine(ex);
	}
}
