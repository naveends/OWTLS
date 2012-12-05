import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;


public class Alice{

	X509Certificate myCert = null;
	X509Certificate otherCert = null;
	RSAPrivateKey myPrivateKey = null;
	boolean error;
	long masterKey;
	String fileName;

	Socket socket = null;
	DataInputStream dis = null;
	DataOutputStream dos = null;

	Alice(boolean errorVal, String fileName) {
		error = errorVal;
		/*Thread t = new Thread(this);
		t.start();*/
		this.fileName = fileName;
	}

	public int connectToServer() {
		CertificateFactory cert = null;
		InputStream certStream = null;
		int len = 0;
		String path = Utility.getCurrentExecutionPath();

		System.out.println("*************** Starting Handshake Phase*************** \n");

		/*------------------------------- HANDSHAKE PHASE -------------------------------------*/

		try {
			certStream = new FileInputStream(path + "/Files/alice.der");
			cert = CertificateFactory.getInstance("X.509");
			myCert = (X509Certificate)cert.generateCertificate(certStream);
			certStream.close();


			File f = new File(path + "/Files/alice.key8");
			FileInputStream fis = new FileInputStream(f);
			DataInputStream dis = new DataInputStream(fis);

			byte[] keyBytes = new byte[(int) f.length()];
			dis.readFully(keyBytes);
			dis.close();

			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			myPrivateKey = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);

		} catch (CertificateException e) {
			e.printStackTrace();
			return -1;
		} catch (IOException e) {
			e.printStackTrace();
			return -1;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return -1;
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
			return -1;
		}

		// try to connect to Bob			
		InetAddress addr;
		try {
			//String ipAddress = "10.0.0.5";
			String ipAddress = "192.168.137.1";
			socket = new Socket(ipAddress, Utility.B_PORT);
		} catch (UnknownHostException e) {
			e.printStackTrace();
			return -1;
		} catch (IOException e) {
			e.printStackTrace();
			return -1;
		}

		dis = null;
		dos = null;
		MessageDigest sha1;
		try {
			sha1 = MessageDigest.getInstance("SHA1");



			long aliceNonce = Utility.get_nonce();
			long bobNonce;			
			long S = Utility.get_nonce();
			dis = new DataInputStream(socket.getInputStream());
			dos = new DataOutputStream(socket.getOutputStream());


			// (1). sending Certificate to Bob
			System.out.println("[Alice] : Sending Certificate, Cipher Suite");
			byte[] certEncoded = myCert.getEncoded();
			dos.writeInt(certEncoded.length);
			sha1.update(ByteBuffer.allocate(4).putInt(certEncoded.length).array());

			if(certEncoded.length > 0)
			{
				dos.write(certEncoded);
				sha1.update(certEncoded);
			}

			// (1). b. sending encryption and integrity protection choices
			dos.write(0x0A);
			sha1.update((byte) 0x0A);

			// (2). read Bob's certificate now
			len = dis.readInt();
			sha1.update(ByteBuffer.allocate(4).putInt(len).array());
			certEncoded = new byte[len];
			if (len > 0)
			{
				dis.readFully(certEncoded);
				sha1.update(certEncoded);
			}
			System.out.println("[Alice] : Recieved Bob's Certificate..\n");

			certStream = new ByteArrayInputStream(certEncoded);
			otherCert = (X509Certificate)cert.generateCertificate(certStream);
			certStream.close();
			//System.out.println("[Alice] : Received Bob's certificate");

			// 3. Send my nonce, encrypted using Bob's public key
			System.out.println("[Alice] Sending My Nonce [before encryption]: " + Long.toString(aliceNonce));
			RSAPublicKey otherPubKey = (RSAPublicKey)otherCert.getPublicKey();

			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, otherPubKey);
			byte[] myEncryptedNonce = cipher.doFinal(ByteBuffer.allocate(8).putLong(aliceNonce).array());
			dos.writeInt(myEncryptedNonce.length);
			sha1.update(ByteBuffer.allocate(4).putInt(myEncryptedNonce.length).array());
			if(myEncryptedNonce.length > 0)
			{
				dos.write(myEncryptedNonce);
				sha1.update(myEncryptedNonce);  // update SHA
				if(error == true) // to introduce error, this message gets SHA'd twice
					sha1.update(myEncryptedNonce);					
			}

			//(3). Get Bob's nonce and decrypt it using my private key
			len = dis.readInt();
			sha1.update(ByteBuffer.allocate(4).putInt(len).array());
			byte[] bobNonceEncrypted = new byte[len];
			if (len > 0)
			{
				dis.readFully(bobNonceEncrypted);
				sha1.update(bobNonceEncrypted);					
			}
			// (b). decrypt the received noce
			cipher.init(Cipher.DECRYPT_MODE, myPrivateKey);
			bobNonce = ByteBuffer.wrap(cipher.doFinal(bobNonceEncrypted)).getLong();
			System.out.println("[Alice] : Recieved Bob Nonce [after decryption] : " + bobNonce + "\n");

			// send secret S encrypted with public key of Bob, not included in SHA calculation
			System.out.println("[Alice] : Sending {S}pubKey_Bob, keyed hash of handshake messages..");
			cipher.init(Cipher.ENCRYPT_MODE, otherPubKey);
			byte[] myEncryptedSecret = cipher.doFinal(ByteBuffer.allocate(8).putLong(S).array());
			dos.writeInt(myEncryptedSecret.length);
			if(myEncryptedSecret.length > 0)
				dos.write(myEncryptedSecret);

			// set the master key now, as you have both R_Alice and R_Bob
			masterKey = S ^ aliceNonce ^ bobNonce;
			sha1.update(ByteBuffer.allocate(8).putLong(masterKey).array());   // till here, now sha1 is hash of
			//master secret K and handshake messages
			System.out.println("[Alice] : Master secret created\n");	
			MessageDigest aliceSHA = (MessageDigest) sha1.clone();
			MessageDigest bobSHA = (MessageDigest) sha1.clone();

			aliceSHA.update("CLIENT".getBytes("UTF-8")); // hash of what Alice will send
			bobSHA.update("SERVER".getBytes("UTF-8")); // hash of what Bob will send and Alice would receive
			byte[] aliceHash = aliceSHA.digest();
			byte[] checkBobHash = bobSHA.digest();

			// send hash to Bob
			dos.writeInt(aliceHash.length);
			dos.write(aliceHash);	

			// recieve Bob's Hash
			len = dis.readInt();
			byte[] bobHash = new byte[len];
			if(len>0) {
				dis.readFully(bobHash);
			}

			System.out.println("[Alice] :  Recieved keyed hash from Bob ");
			// match the recieved hash with hash calculated.. if they match, perfect!
			// if they not match, close all connections and quit...
			if(Arrays.equals(checkBobHash, bobHash)) {
				System.out.println("[Alice] : HASH MATCHED \n");
			} else {
				System.out.println("[Alice] : keyed Hash received does not match!!!! quitting...");
				dis.close();
				dos.close();
				socket.close();
				System.out.println("[Alice] : Closed connection with Bob...");
				return -1;
			}							

			/*------------------------ HANDSHAKE PHASE END ------------------------*/

			/* ----------------------- DATA TRANSFER PHASE ----------------------- */

		
			// load file to send
						
						File fileToSend =  new File("Picture.jpg");
						byte[] nameOfFile = fileName.getBytes("UTF-8");
						byte[] fileBytes = Utility.readBytesFromFile(fileToSend);
						
						if(sendData(fileBytes, nameOfFile))
						{	
							System.out.println("Received Success From Bob");
							return 0;
						}	
			/*---------------------------- DATA TRANSFER PHASE END --------------------------  */
					
						

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (EOFException e) {	
			System.out.println("[Alice] : Quitting... Hash Mismatch... ");				
		} catch (IOException e) {	
			System.out.println("Transferred..");
			//e.printStackTrace();
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (CloneNotSupportedException e) {
			e.printStackTrace();
		} catch (Exception e) {				
			e.printStackTrace();
		} 
		
		return -1;
	}
	
	public boolean sendData(byte[] fileBytes, byte[] filename) {
				
		byte[] clientEncryptionKey = new byte[24];
		byte[] clientAuthenticationKey = new byte[24];
		SecureRandom sec;
		try {
			sec = SecureRandom.getInstance("SHA1PRNG");
		
		
		sec.setSeed(masterKey);

		sec.nextBytes(clientAuthenticationKey);
		sec.nextBytes(clientEncryptionKey);
		
		// Prepare to check the SSL data record MAC for our SSL data records
		Mac hmac;
		hmac = Mac.getInstance("HmacSHA1");
		
		SecretKeySpec secret = new SecretKeySpec(clientAuthenticationKey,"HmacSHA1");
		hmac.init(secret);
		
		
		byte [] encryptedToTransfer = Utility.encrypt(fileBytes, clientEncryptionKey);
		
		// send filename
		dos.writeInt(filename.length);
		dos.write(filename);
		
		// send header (type, version number, length)
		dos.write((byte)0x18);	// close data
		dos.write((byte)0x01); // SSL Major version 1
		dos.write((byte)0x00); // SSL Minor version 0
		dos.writeInt(encryptedToTransfer.length);
		
		// Send the data
		dos.write(encryptedToTransfer);
		
		// Send the MAC
		hmac.reset();
		hmac.update(fileBytes, 0, fileBytes.length);
		byte[] digest = hmac.doFinal();
		dos.write(digest);
		System.out.println("[Alice] : File transferred..");

		System.out.println("[Alice] Waiting for response from Server");
		int returnCode = dis.readInt();
		
		if(returnCode == 0)
			return true;
		return false;
		
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (EOFException e) {	
			System.out.println("[Alice] : Quitting... Hash Mismatch... ");		
			e.printStackTrace();
		} catch (IOException e) {	
			e.printStackTrace();
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (CloneNotSupportedException e) {
			e.printStackTrace();
		} catch (Exception e) {				
			e.printStackTrace();
		}
		return false; 
	}


}
