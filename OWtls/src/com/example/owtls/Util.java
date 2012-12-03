package com.example.owtls;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Util
{
	public static final int PORT_OF_BOB = 9999;
	public static boolean error = false;

	public static String getCurrentExecutionPath()
	{
		return System.getProperty("user.dir");
	}

	public static String byteArrayToHexString(byte[] b) throws Exception
	{
		String result = "";
		for (int i=0; i < b.length; i++)
		{
			result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
		}
		return result;
	}

	public static byte[] getBytesFromFile(File file) throws IOException, FileNotFoundException
	{
		FileInputStream fin = new FileInputStream(file);
		byte data[] = new byte[(int)file.length()];

		fin.read(data);

		return data;
	}

	public static byte[] encrypt(String message, byte[] key) throws Exception
	{
		return encrypt(message.getBytes("UTF-8"), key);
	}

	public static byte[] encrypt(byte[] message, byte[] key) throws Exception
	{
		byte[] keyEnc = new byte[24];
		keyEnc = Arrays.copyOfRange(key, 0, 24);
		final SecretKey secretKey = new SecretKeySpec(keyEnc, "DESede");

		final Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
		final IvParameterSpec iv = new IvParameterSpec(new byte[cipher.getBlockSize()]); 
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

		final byte[] cipherText = cipher.doFinal(message);

		return cipherText;
	}

	public static byte[] decrypt(byte[] message, byte[] key) throws NoSuchAlgorithmException, NoSuchPaddingException 
	{
		byte[] keyDec = new byte[24];
		keyDec = Arrays.copyOfRange(key, 0, 24);
		final SecretKey secretKey = new SecretKeySpec(keyDec, "DESede");
		final Cipher decipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
		final IvParameterSpec iv = new IvParameterSpec(new byte[decipher.getBlockSize()]); // Setting IV to 0
		System.out.println("Before drcrypt");
		try {
			decipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		try {
			return decipher.doFinal(message);
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public static String byteArrayToString(byte[] stringBytes) throws UnsupportedEncodingException 
	{
		return new String(stringBytes, "UTF-8");
	}

	public static Long pow(long a, long g) {

		long num = g, answer = num;
		long mod = 159197;
		int counter = 1;
		String bin_pow = Long.toBinaryString(a);
		int length = bin_pow.length();
		while ((length-1) != 0)
		{
			String subStr = bin_pow.substring(counter, counter+1);
			if (subStr.compareTo("0") == 0)
			{
				answer = (answer * answer) % mod;
			}
			else
			{
				answer = ((((answer * answer) % mod) * num) % mod);
			}
			counter++;
			length--;

		}
		return answer;
	}
	
	/**
	 * This method is supposed to do the keyed-hash of the string s with the key keyString
	 * @param s is the message whose hash is required
	 * @param keyString is the key to be used for hash computation
	 * @param type is the hash type, either SHA1 or SHA256
	 * @return returns the keyed hash of the message
	 * @throws UnsupportedEncodingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public static byte[] sha1(String s, String keyString, String type) throws UnsupportedEncodingException, 
	NoSuchAlgorithmException, InvalidKeyException {

		//System.out.println(keyString + "   " +s);

		SecretKeySpec key = new SecretKeySpec((keyString).getBytes("UTF-8"), type);
		Mac mac = Mac.getInstance(type);
		mac.init(key);

		byte[] bytes = mac.doFinal(s.getBytes("UTF-8"));

		return bytes;

	}
	
	//this is for shabyte, takes the key as bytes
	/**
	 * //this is for shabyte, takes the key as bytes
	 * @param s
	 * @param keyString
	 * @param type
	 * @return
	 * @throws UnsupportedEncodingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public static byte[] shaByte(String s, byte[] keyString, String type) throws UnsupportedEncodingException, 
	NoSuchAlgorithmException, InvalidKeyException {

		//System.out.println(keyString + "   " +s);

		SecretKeySpec key = new SecretKeySpec(keyString, type);
		Mac mac = Mac.getInstance(type);
		mac.init(key);

		byte[] bytes = mac.doFinal(s.getBytes("UTF-8"));

		return bytes;

	}
	
	public static byte[] compress(byte[] input) {

		 // Compress the bytes
		 byte[] output = new byte[447];
		 Deflater compresser = new Deflater();
		 compresser.setInput(input);
		 compresser.finish();
		 int compressedDataLength = compresser.deflate(output);
		 System.out.println("Compressed data length is " + compressedDataLength);

		 // Decompress the bytes
		 Inflater decompresser = new Inflater();
		 decompresser.setInput(output, 0, compressedDataLength);
		 byte[] result = new byte[1024];
		 try {
			int resultLength = decompresser.inflate(result);
		} catch (DataFormatException e) {
			e.printStackTrace();
		}
		 decompresser.end();

		 return result;
	}
	

}

