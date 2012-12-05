import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class Utility {
	
	public static final Integer A_PORT = 7777;
	public static final Integer B_PORT = 8888;
	
	public static String getCurrentExecutionPath()
    {
            return System.getProperty("user.dir");
    }
	
	public static long get_nonce() {
		SecureRandom secRandom = new SecureRandom();
		long nonce = secRandom.nextLong();		//generates a 64-bit random nonce value
		return Math.abs(nonce);
	}
	
	public static String byteArrayToHexString(byte[] b)
	{
		StringBuffer result = new StringBuffer();
		for (int i=0; i < b.length; i++)
		{
			result.append(Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1));
		}
		return result.toString();
	}
	
	public static String byteArrayToString(byte[] b) throws Exception {
		return new String(b,"UTF-8"); 
	}
	
	public static byte[] readBytesFromFile(File file) throws IOException {
		byte[] fileBytes = new byte[(int) file.length()];
		FileInputStream fin = new FileInputStream(file);
		fin.read(fileBytes);
		return fileBytes;		
	}
	
	public static byte[] encrypt(String message, byte[] key) throws Exception
	{
		return encrypt(message.getBytes("UTF-8"), key);
    	}
	
	public static byte[] encrypt(byte[] message, byte[] key) throws Exception
	{
		final SecretKey skey = new SecretKeySpec(key, "DESede");
		
		final Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
		final IvParameterSpec iv = new IvParameterSpec(new byte[8]); // Setting IV to 0
		cipher.init(Cipher.ENCRYPT_MODE, skey, iv);
		
		final byte[] cipherText = cipher.doFinal(message);

		return cipherText;
	}
    
	public static byte[] decrypt(byte[] message, byte[] key) throws Exception
	{
		final SecretKey skey = new SecretKeySpec(key, "DESede");
		final Cipher decipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
		final IvParameterSpec iv = new IvParameterSpec(new byte[8]); // Setting IV to 0
		decipher.init(Cipher.DECRYPT_MODE, skey, iv);
		return decipher.doFinal(message);
	}
	
	
	
	

}
