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