import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
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

public class Bob implements Runnable {
	private Socket connectionSocket = null;	
	X509Certificate myCert = null;
	X509Certificate clientCert = null;
	RSAPrivateKey myPrivateKey = null;


	Bob() {
		Thread t = new Thread(this);
		t.start();
	}

	ServerSocket serverSocket1 = null;
	protected void finalize()
	{
		try {
			serverSocket1.close();
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}


	public void run()
	{
		try {
			serverSocket1 = new ServerSocket(Utility.B_PORT);
		}
		catch (IOException e) {
			e.printStackTrace();
			return;
		}

		int i = 0;
		while(true) {
			try
			{	// listen for connection, if one appears, accept it and break    		
				connectionSocket = serverSocket1.accept();
				new ServerSocketWorker(connectionSocket);
			}
			catch (IOException e)
			{
				System.out.println("Unable to connect .. Some error" );
				System.err.println(e);
				return;
			}
		}
	}

	public class ServerSocketWorker implements Runnable {

		private Socket connectionSocket;
		ServerSocketWorker(Socket s) {
			connectionSocket = s;
			Thread t = new Thread(this);
			t.start();
		}
		
		public void run() {
			CertificateFactory cert = null;
			InputStream certStream = null;
			int len = 0;
			String path = Utility.getCurrentExecutionPath();

			try {
				// generate Certificates
				certStream = new FileInputStream(path + "/Files/bob.der");
				cert = CertificateFactory.getInstance("X.509");
				myCert = (X509Certificate)cert.generateCertificate(certStream);
				certStream.close();

				File f = new File(path + "/Files/bob.key8");
				FileInputStream fis = new FileInputStream(f);
				DataInputStream dis = new DataInputStream(fis);

				// key bytes
				byte[] keyBytes = new byte[(int) f.length()];
				dis.readFully(keyBytes);
				dis.close();

				PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
				KeyFactory keyFactory = KeyFactory.getInstance("RSA");
				myPrivateKey = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);

			} catch (CertificateException e) {
				e.printStackTrace();
				return;
			} catch (IOException e) {
				e.printStackTrace();	
				return;
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
				return;
			} catch (InvalidKeySpecException e) {
				e.printStackTrace();
				return;
			}

			DataInputStream dis = null;
			DataOutputStream dos = null;
			long aliceNonce;
			long bobNonce = Utility.get_nonce();
			long S;
			long masterKey;

			try {
				dis = new DataInputStream(connectionSocket.getInputStream());
				dos = new DataOutputStream(connectionSocket.getOutputStream());

				MessageDigest sha1 = MessageDigest.getInstance("SHA1");

				// (1).(a). read Alice's certificate bytes, update SHA
				len = dis.readInt();
				sha1.update(ByteBuffer.allocate(4).putInt(len).array());
				byte[] encodedCert = new byte[len];
				if(len>0) {
					dis.readFully(encodedCert);
					sha1.update(encodedCert);
				}

				// (b).generate Alice's certificate from the recieved message
				certStream = new ByteArrayInputStream(encodedCert);
				clientCert = (X509Certificate)cert.generateCertificate(certStream);
				certStream.close();

				// (c).receive cipher_suite from Alice, and update the SHA 
				byte ciphersuite = dis.readByte();
				if(ciphersuite == 0x0A)
					sha1.update((byte) 0x0A);
				else
				{
					// not recieved ciphersuite 0x0A, Bob has only 1 cipher suite [SHA,RSA] (similar to Alice's, so update SHA to that)
					sha1.update((byte) 0x0A);

				}
				System.out.println("[SERVER] : Recieved Alice Certificate and Cipher Suite\n");

				// (2). sending my certificate now (Bob's)
				System.out.println("[SERVER] : Sending Certificate");
				encodedCert = myCert.getEncoded();
				dos.writeInt(encodedCert.length);
				sha1.update(ByteBuffer.allocate(4).putInt(encodedCert.length).array());
				if(encodedCert.length>0) {
					dos.write(encodedCert);
					sha1.update(encodedCert);
				}

				// (4). (a). recieve nonce, and decrypt it
				len = dis.readInt();
				sha1.update(ByteBuffer.allocate(4).putInt(len).array());

				byte[] nonceFromAliceEncrypted = new byte[len];
				if (len > 0)
				{
					dis.readFully(nonceFromAliceEncrypted);
					sha1.update(nonceFromAliceEncrypted);				
				}

				Cipher cipher = Cipher.getInstance("RSA");
				// (b). decrypting Alice's received nonce with my private key 
				cipher.init(Cipher.DECRYPT_MODE, myPrivateKey);
				aliceNonce = ByteBuffer.wrap(cipher.doFinal(nonceFromAliceEncrypted)).getLong();
				System.out.println("[SERVER] : Recieved Alice's Nonce [after decryption] : " + Long.toString(aliceNonce) + "\n");


				// (3). Bob sends his nonce encrypted with Alice's public key
				// we get the public key from the certificate received
				System.out.println("[SERVER] : Sending my nonce [before encryption] : " + Long.toString(bobNonce));
				RSAPublicKey publickey = (RSAPublicKey) clientCert.getPublicKey();				
				cipher.init(Cipher.ENCRYPT_MODE, publickey);
				byte[] encryptedNonce = cipher.doFinal(ByteBuffer.allocate(8).putLong(bobNonce).array());
				dos.writeInt(encryptedNonce.length);
				// also update SHA as soon as you encrypt it, first its length and then the actual encypted data
				sha1.update(ByteBuffer.allocate(4).putInt(encryptedNonce.length).array());			
				if(encryptedNonce.length>0) {
					dos.write(encryptedNonce);
					sha1.update(encryptedNonce);
				}

				// read encrypted S, decrypt it to find secret S
				len = dis.readInt();
				byte[] encryptedS = new byte[len];
				if(len>0)
					dis.readFully(encryptedS);
				cipher.init(Cipher.DECRYPT_MODE, myPrivateKey);
				S = ByteBuffer.wrap(cipher.doFinal(encryptedS)).getLong();

				// set the master key now, as you have all S, R_Alice and R_Bob
				masterKey = S ^ aliceNonce ^ bobNonce;
				sha1.update(ByteBuffer.allocate(8).putLong(masterKey).array());
				System.out.println("[SERVER] : Master secret created\n");

				// update hashes
				MessageDigest bobSHA = (MessageDigest) sha1.clone();
				MessageDigest aliceSHA = (MessageDigest) sha1.clone();

				bobSHA.update("SERVER".getBytes("UTF-8")); // hash of what Bob will send
				byte[] bobHash = bobSHA.digest();

				aliceSHA.update("CLIENT".getBytes("UTF-8")); // hash of what Alice will send and Bob would receive
				byte[] checkAliceHash = aliceSHA.digest();

				// read Alice's Hash
				len = dis.readInt();
				byte[] aliceHash = new byte[len];
				if(len > 0)
					dis.readFully(aliceHash);

				System.out.println("[SERVER] : Recieved {S}pubKey_bob, keyed hash of handshake messages from Alice\n");
				// check for correctness of hash
				if(Arrays.equals(aliceHash, checkAliceHash)) {
					System.out.println("[SERVER] : HASH MATCHED... Sending my keyed hash now.. \n");
				} else {
					// close connections
					System.out.println("[SERVER] : Hash received does not match!!!! quitting...");
					dis.close();
					dos.close();

					System.out.println("[SERVER] : Closed connection with Bob...");
					return;
				}

				// send Bob hash 
				dos.writeInt(bobHash.length);
				dos.write(bobHash);

				/*------------------------ HANDSHAKE PHASE END ------------------------*/

				/* ----------------------- DATA TRANSFER PHASE ----------------------- */

				System.out.println("\n *************** Starting Data Transfer Phase*************** \n");

				byte[] clientEncryptionKey = new byte[24];
				byte[] clientAuthenticationKey = new byte[24];
				SecureRandom sec = SecureRandom.getInstance("SHA1PRNG");
				sec.setSeed(masterKey);

				sec.nextBytes(clientAuthenticationKey);
				sec.nextBytes(clientEncryptionKey);

				Mac hmac = Mac.getInstance("HmacSHA1");
				SecretKeySpec secret = new SecretKeySpec(clientAuthenticationKey,"HmacSHA1");
				hmac.init(secret);			

				// read file name
				int filenamelength = dis.readInt();
				byte[] filenamebytes = new byte[filenamelength]; 
				dis.readFully(filenamebytes);

				String fileString;
				fileString = Utility.byteArrayToString(filenamebytes);
				System.out.println("FileName = " + fileString);
				// Start getting the file, with header first (message type, version number, length)
				byte messageType = dis.readByte(); 
				byte majorVersion = dis.readByte();
				byte minorVersion = dis.readByte();

				int encryptedDataLength = dis.readInt();			
				byte[] encryptedData = new byte[encryptedDataLength];

				// Read the encrypted data
				dis.readFully(encryptedData);

				// Decrypt the data and check the MAC
				byte [] decryptedBytes = Utility.decrypt(encryptedData, clientEncryptionKey);

				hmac.reset();
				byte[] checkDigest = hmac.doFinal(decryptedBytes);

				byte[] messageAuthenticationCode = new byte[20];
				dis.read(messageAuthenticationCode);

				// Save the new data into the file if MAC is correct, otherwise exit
				if(Arrays.equals(checkDigest, messageAuthenticationCode))
				{
					System.out.println("[SERVER] : MAC Matched... file safe..");
				}
				else
				{
					System.out.println("[SERVER] : MAC on data was incorrect!.. quitting");
					dos.close();
					dis.close();
					//socket.close();
					return;
				}
				
				// save the read file in a new file
				File recievedFile = new File(path + "/Files/pictures/" + fileString);
				FileOutputStream out = new FileOutputStream(recievedFile);
				out.write(decryptedBytes);
				System.out.println("[SERVER] : File saved in pictures folder!!");
				dos.writeInt(0);
				Thread imageThread = new Images();
				imageThread.start();
				
				System.out.println("Sending response to Gateway");
				

				/*---------------------------- DATA TRANSFER PHASE END --------------------------  */

			} catch (EOFException e) {	
				System.out.println("[SERVER] : Quitting... Hash Mismatch... ");				
			} catch (IOException e) {
				e.printStackTrace();
				return;				
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (CertificateEncodingException e) {
				e.printStackTrace();
			} catch (CertificateException e) {
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				e.printStackTrace();
			} catch (InvalidKeyException e) {
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




		}

	}
}


