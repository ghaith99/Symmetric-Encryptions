using System;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.IO;

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

	public enum AlgorithmCipherMode
	{
		CBC,
		ECB,
		CFB
	}

	public enum AlgorithmPaddingMode
	{
		None,
		PKCS7,
		Zeros,
		ANSIX923,
		ISO10126
	}

	public enum SymmetricAlgorithmForAction
	{
		AES,
		DES,
		RC2,
		Rijndael,
		TripleDES
	}

	public static Dictionary<EncryptionEncoding, Encoding> EncodingMapping;
	public static Dictionary<AlgorithmCipherMode, CipherMode> CipherModeMapping;
	public static Dictionary<AlgorithmPaddingMode, PaddingMode> PaddingModeMapping;
	public static void Main()
	{
		MapEncryptionEncodingEnums();
	}

	public static void EncryptFromFile(String fileToEncrypt, String varEncryptionKey, ref String encryptedText, ref String salt, ref String initializationVector, int encoding, int encryptionAlgorithm, string encryptionKey, int blockSize, int keySize, int cipherMode, int paddingMode, bool useSalt, bool useIv)
	{
		FileInfo fileVariant = new FileInfo(fileToEncrypt);
		Encoding encoding2 = EncodingMapping[(EncryptionEncoding)encoding];
		CipherMode cipherMode2 = CipherModeMapping[(AlgorithmCipherMode)cipherMode];
		PaddingMode paddingMode2 = PaddingModeMapping[(AlgorithmPaddingMode)paddingMode];
		try
		{
			if (!fileVariant.Exists)
			{
				Console.WriteLine(string.Format("File {0} does not exist", fileVariant));
				return;
			}

			byte[] dataBytes = ReadFileBytes(fileVariant.FullName, encoding2);
			string key = encryptionKey;
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

	private static byte[] ReadFileBytes(string fileName, Encoding encoding)
	{
		byte[] bytes;
		using (StreamReader streamReader = new StreamReader(File.OpenRead(fileName), encoding))
		{
			string s = streamReader.ReadToEnd();
			bytes = encoding.GetBytes(s);
		}

		return bytes;
	}

	private static System.ValueTuple<string, string, string> EncryptDataImp(Encoding encoding, SymmetricAlgorithmForAction encryptionAlgorithm, int blockSize, int keySize, CipherMode cipherMode, PaddingMode paddingMode, byte[] dataBytes, string key, bool useSalt, bool useIv)
	{
		byte[] array;
		byte[] array2;
		byte[] inArray;
		using (SymmetricAlgorithm symmetricAlgorithm = GetSymmetricAlgorithm(encryptionAlgorithm))
		{
			symmetricAlgorithm.KeySize = keySize;
			symmetricAlgorithm.BlockSize = blockSize;
			symmetricAlgorithm.Mode = cipherMode;
			symmetricAlgorithm.Padding = paddingMode;
			int num = symmetricAlgorithm.KeySize / 8;
			array = (useSalt ? GenerateBitsOfRandomEntropy(num) : new byte[num]);
			byte[] bytes;
			if (useSalt)
			{
				using (Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(key, array, 1000))
				{
					bytes = rfc2898DeriveBytes.GetBytes(num);
					goto IL_B3;
				}
			}

			bytes = encoding.GetBytes(key);
			if (bytes.Length < num)
			{
				int num2 = symmetricAlgorithm.LegalKeySizes[0].MinSize / 8;
				if (encryptionAlgorithm != SymmetricAlgorithmForAction.TripleDES)
				{
					Array.Resize<byte>(ref bytes, num);
				}
				else if (bytes.Length < num2)
				{
					Array.Resize<byte>(ref bytes, num2);
				}
			}

			IL_B3:
				symmetricAlgorithm.Key = bytes;
			int num3 = symmetricAlgorithm.BlockSize / 8;
			array2 = (useIv ? GenerateBitsOfRandomEntropy(num3) : new byte[num3]);
			symmetricAlgorithm.IV = array2;
			using (ICryptoTransform cryptoTransform = symmetricAlgorithm.CreateEncryptor())
			{
				using (MemoryStream memoryStream = new MemoryStream())
				{
					using (CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Write))
					{
						cryptoStream.Write(dataBytes, 0, dataBytes.Length);
						cryptoStream.FlushFinalBlock();
						inArray = memoryStream.ToArray();
						memoryStream.Close();
						cryptoStream.Close();
					}
				}
			}
		}

		return new System.ValueTuple<string, string, string>(Convert.ToBase64String(inArray), Convert.ToBase64String(array), Convert.ToBase64String(array2));
	}

	private static SymmetricAlgorithm GetSymmetricAlgorithm(SymmetricAlgorithmForAction symmetricAlgorithm)
	{
		switch (symmetricAlgorithm)
		{
			case SymmetricAlgorithmForAction.AES:
				return new AesCryptoServiceProvider();
			case SymmetricAlgorithmForAction.DES:
				return new DESCryptoServiceProvider();
			case SymmetricAlgorithmForAction.RC2:
				return new RC2CryptoServiceProvider();
			case SymmetricAlgorithmForAction.Rijndael:
				return new RijndaelManaged();
			case SymmetricAlgorithmForAction.TripleDES:
				return new TripleDESCryptoServiceProvider();
			default:
				throw new InvalidOperationException();
		}
	}

	private static byte[] GenerateBitsOfRandomEntropy(int bytes)
	{
		byte[] array = new byte[bytes];
		using (RNGCryptoServiceProvider rngcryptoServiceProvider = new RNGCryptoServiceProvider())
		{
			rngcryptoServiceProvider.GetBytes(array);
		}

		return array;
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
		//Mapping enums from 0 based counting to system 1 based counting (could have been replaced with +1 everywhere!!)
		CipherModeMapping = new Dictionary<AlgorithmCipherMode, CipherMode>();
		CipherModeMapping[AlgorithmCipherMode.CBC] = CipherMode.CBC;
		CipherModeMapping[AlgorithmCipherMode.ECB] = CipherMode.ECB;
		CipherModeMapping[AlgorithmCipherMode.CFB] = CipherMode.CFB;
		//Mapping enums from 0 based counting to system 1 based counting (could have been replaced with +1 everywhere!!)
		PaddingModeMapping = new Dictionary<AlgorithmPaddingMode, PaddingMode>();
		PaddingModeMapping[AlgorithmPaddingMode.None] = PaddingMode.None;
		PaddingModeMapping[AlgorithmPaddingMode.PKCS7] = PaddingMode.PKCS7;
		PaddingModeMapping[AlgorithmPaddingMode.Zeros] = PaddingMode.Zeros;
		PaddingModeMapping[AlgorithmPaddingMode.ANSIX923] = PaddingMode.ANSIX923;
		PaddingModeMapping[AlgorithmPaddingMode.ISO10126] = PaddingMode.ISO10126;
	}
}