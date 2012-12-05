import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.HashMap;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class GatewayOfIndia implements Runnable
{
	HashMap<String, Boolean> files = new HashMap<String, Boolean>();
	ServerSocket serverSocket = null;
	GatewayOfIndia()
	{
		Thread t = new Thread(this);
		t.start();
	}

	protected void finalize()
	{
		try
		{
			serverSocket.close();
		}
		catch (IOException e)
		{
			e.printStackTrace();
			return;
		}
	}

	public void run()
	{
		try
		{
			serverSocket = new ServerSocket(Util.PORT_OF_BOB);
		}
		catch (IOException e)
		{
			e.printStackTrace();
			return;
		}
		int i = 0;
		while(true)
		{
			Socket connectionSocket = null;
			try
			{
				connectionSocket = serverSocket.accept();
				new BobSocketWorker(connectionSocket, i++);
				System.out.println("Connection Established...");
			}
			catch (IOException e)
			{
				e.printStackTrace();
				return;
			}
		}
	}

	public class BobSocketWorker implements Runnable, Serializable
	{
		long p = 159197;
		long g = 33677;
		byte [] secretKey;
		byte [] clientEncryptionKey;
		byte [] clientIntegrityKey;
		byte [] serverEncryptionKey;
		byte [] serverIntegrityKey;
		byte [] sessionId;

		SessionSerialization serializer = new SessionSerialization();
		CertificateFactory certificateFactory = null;
		InputStream certificateStream;
		X509Certificate bobCertificate = null;
		RSAPrivateKey bobPrivateKey = null;
		X509Certificate aliceCertificate = null;
		String executionPath = Util.getCurrentExecutionPath();
		InputStream in = null;
		DataInputStream dis = null;
		OutputStream out = null;
		DataOutputStream dos = null;

		private Socket connectionSocket;
		BobSocketWorker(Socket s, int newi)
		{
			connectionSocket = s;
			Thread t = new Thread(this);
			t.start();
		}

		protected void finalize()
		{
			try
			{
				connectionSocket.close();
			}
			catch (IOException e)
			{
				e.printStackTrace();
			}
		}


		private void doSerialize(byte [] sessionId, String name)
		{
			Session session = new Session(sessionId, name);
			serializer.serialize(session);
		}


		private void buildCertificates()
		{
			try
			{
				// read the certificate
				certificateStream = new FileInputStream(executionPath+"/sslFiles/bob.der");
				certificateFactory = CertificateFactory.getInstance("X.509");
				bobCertificate = (X509Certificate)certificateFactory.generateCertificate(certificateStream);
				certificateStream.close();

				// Load my key
				File f = new File(executionPath+"/sslFiles/bob.key8");
				FileInputStream fis = new FileInputStream(f);
				dis = new DataInputStream(fis);
				byte[] keyBytes = new byte[(int)f.length()];
				dis.readFully(keyBytes);
				dis.close();

				PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
				KeyFactory kf = KeyFactory.getInstance("RSA");
				bobPrivateKey = (RSAPrivateKey) kf.generatePrivate(spec);
			} catch (FileNotFoundException e) {
				e.printStackTrace();
				return;
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

		}

		private void createConnection()
		{
			try
			{
				in = connectionSocket.getInputStream();
				dis = new DataInputStream(in);
				out = connectionSocket.getOutputStream();
				dos = new DataOutputStream(out);
				//io established 
			}
			catch (IOException e)
			{
				e.printStackTrace();
				return;
			}
		}

		public void run()
		{
			String beforeHash = "";
			buildCertificates();
			createConnection();


			int lengthOfMessage =0;
			byte [] tmpBufferArray = null;
			SecureRandom randomNumber = new SecureRandom();
			String delim = ",";
			boolean isOldSessionResumed = false;

			//read 0 message
			try
			{
				int decisionToken = dis.readInt();
				System.out.println("Flag read:"+decisionToken);
				beforeHash = "";
				if(decisionToken ==1)
				{
					isOldSessionResumed = true;
				}
				else if(decisionToken ==0)
					isOldSessionResumed = false;
				else
				{
					System.err.println("Some rogue signal received. Closing connections...");
					dis.close();
					dos.close();
				}
			}
			catch(Exception e)
			{
				e.printStackTrace();
			}

			try
			{
				// read Client's first message which is length of rc and ciphers
				long rClient=-1;
				byte [] shaHashed = null;
				long gamodp=-1;
				long gabModP=-1;
				int b=-1;
				long rServer = -1;
				Base64 b2 = new Base64();


				if(!isOldSessionResumed)
				{
					lengthOfMessage = dis.readInt();
					beforeHash +=String.valueOf(lengthOfMessage);
					System.out.println("Sha1:"+Util.byteArrayToHexString(beforeHash.getBytes()));
					tmpBufferArray = new byte[lengthOfMessage];
					dis.readFully(tmpBufferArray);
					beforeHash += Util.byteArrayToString(tmpBufferArray);
					System.out.println("Sha2:"+Util.byteArrayToHexString(beforeHash.getBytes()));

					String lengthString = Util.byteArrayToString(tmpBufferArray);
					String [] lengths = lengthString.split(delim);
					rClient = Long.parseLong(lengths[0].trim());
					String cipherChosen =  lengths[1].trim();
					
					System.out.println(rClient);
					System.out.println(cipherChosen);
				}
				else
				{
					lengthOfMessage = dis.readInt();
					beforeHash +=String.valueOf(lengthOfMessage);
					System.out.println("[Session Resumed] Sha1:"+Util.byteArrayToHexString(beforeHash.getBytes()));

					tmpBufferArray = new byte[lengthOfMessage];
					dis.readFully(tmpBufferArray);
					beforeHash += Util.byteArrayToString(tmpBufferArray);
					System.out.println("[Session Resumed] Sha2:"+Util.byteArrayToHexString(beforeHash.getBytes()));

					String message = Util.byteArrayToString(tmpBufferArray);
					System.out.println("[Session Resumed] The string form of the received message:"+message);

					String [] lengths = message.split(delim);
					String sessionIdString = lengths[0];

					sessionId =b2.decode(sessionIdString);
					//sessionId = sessionIdString.getBytes();
					System.out.println("[fSession Resumed] Session id:"+Util.byteArrayToHexString(sessionId));
					sessionIdString = Util.byteArrayToHexString(sessionId);
					System.out.println("[Session Resumed] Session id in Hex:"+Util.byteArrayToString(sessionId));
					Session retrievedSession = serializer.deserialize(sessionId);
					if(retrievedSession == null)
					{
						System.err.println("No such session exists...Exiting connection.");
						dos.writeInt(-1);
						dis.close();
						dos.close();
					}
					else
					{
						retrievedSession.getSessionKey();
						if(Arrays.equals(retrievedSession.getSessionKey(), sessionId))
						{
							System.out.println("[Session Resumed] The received session id matches with retrieved Session Id");
						}
						else
						{
							System.err.println("Received SessionId does not match with retrieved session id...Exiting connection.");
							dos.writeInt(-1);
							dis.close();
							dos.close();
						}
					}

					rClient = Long.parseLong(lengths[1]);
					System.out.println("[Session Resumed] Client nonce:"+rClient);

					gamodp = Long.parseLong(lengths[2]);
					System.out.println("[Session Resumed] gamodp received:"+gamodp);


				}
				//end of message 1

				//start of message 2
				if(!isOldSessionResumed)
				{
					b = Math.abs(randomNumber.nextInt());
					rServer = randomNumber.nextLong();
					long gbmodp = (Util.pow(Math.abs(b),g)) % p;
					byte[]  certBytes = bobCertificate.getEncoded();

					//for sha..
					beforeHash += String.valueOf(rServer);
					System.out.println("Sha3:"+Util.byteArrayToHexString(beforeHash.getBytes()));
					dos.writeLong(rServer);
					System.out.println("Sending rs:"+rServer);

					int len2 = certBytes.length;
					beforeHash += String.valueOf(len2);
					System.out.println("Sha4:"+Util.byteArrayToHexString(beforeHash.getBytes()));
					dos.writeInt(len2);

					MessageDigest sha1 = null;
					try {
						sha1 = MessageDigest.getInstance("SHA1");
					}catch (NoSuchAlgorithmException e2)
					{
						e2.printStackTrace();
					}
					sha1.update(ByteBuffer.allocate(certBytes.length).put(certBytes).array());
					byte [] keyedHash = sha1.digest();
					beforeHash += Util.byteArrayToHexString(keyedHash);
					System.out.println("SHA5 keyed:"+Util.byteArrayToHexString(beforeHash.getBytes()));
					dos.write(certBytes);

					System.out.println("Sending gbmodp:"+gbmodp);
					beforeHash += String.valueOf(gbmodp);
					System.out.println("Sha6:"+Util.byteArrayToHexString(beforeHash.getBytes()));
					dos.writeLong(gbmodp);
					// sent to client
				}
				else
				{
					b = Math.abs(randomNumber.nextInt());
					rServer = randomNumber.nextLong();
					long gbmodp = (Util.pow(Math.abs(b),g)) % p;
					gabModP = Util.pow(b, gamodp);
					byte []keyedHash =Util.sha1(beforeHash, String.valueOf(gabModP), "HmacSHA1");
					String b64encodedKeyedHash = b2.encodeToString(keyedHash);

					System.out.println("rServer:"+rServer);
					System.out.println("gbmodp:"+gbmodp);
					System.out.println("gabmodp"+gabModP);
					System.out.println("base64 encoded keyed hash:"+b64encodedKeyedHash);

					String messageToSend = String.valueOf(rServer)+delim+String.valueOf(gbmodp)+delim+b64encodedKeyedHash;
					System.out.println("Message to send:"+messageToSend);

					byte [] message = messageToSend.getBytes();
					dos.writeInt(message.length);

					beforeHash += String.valueOf(message.length);
					System.out.println("[Resumed Session]Sha3:"+Util.byteArrayToHexString(beforeHash.getBytes()));

					beforeHash +=Util.byteArrayToString(message);
					System.out.println("[Resumed Session]Sha4:"+Util.byteArrayToHexString(beforeHash.getBytes()));
					dos.write(message);
				}


				//message 3 starts... read from the wireless client
				if(!isOldSessionResumed)
				{
					lengthOfMessage = dis.readInt();
					beforeHash += String.valueOf(lengthOfMessage);
					System.out.println("Sha7:"+Util.byteArrayToHexString(beforeHash.getBytes()));
					System.out.println("length of read message:"+lengthOfMessage);

					byte[] clientEncryptedText = new byte[lengthOfMessage];
					if (lengthOfMessage > 0)
						dis.readFully(clientEncryptedText);				
					beforeHash += Util.byteArrayToHexString(clientEncryptedText);

					System.out.println("Sha8:"+Util.byteArrayToHexString(beforeHash.getBytes()));

					System.out.println("Encrypted text from client:"+Util.byteArrayToHexString(clientEncryptedText));
					Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
					cipher.init(Cipher.DECRYPT_MODE, bobPrivateKey);

					ByteBuffer decryptedMessage = ByteBuffer.wrap(cipher.doFinal(clientEncryptedText));

					gamodp = decryptedMessage.getLong();
					System.out.println("gamodp:"+gamodp);
					long gbModPFromClient =decryptedMessage.getLong();
					System.out.println("gbmodpFromClient:"+gbModPFromClient);

					System.out.println("b:"+b);
					gabModP = Util.pow(b, gamodp);
					System.out.println("GabModb:"+gabModP);
					shaHashed = Util.sha1(beforeHash,String.valueOf(gabModP), "HmacSHA1");
					System.out.println("Shahash calculated at Gateway1:"+Util.byteArrayToString(shaHashed));
					System.out.println(b2.encode(shaHashed));
					System.out.println(b2.encodeToString(shaHashed));
				}
				else
				{
					byte [] keyedHash = Util.sha1(beforeHash, String.valueOf(gabModP), "HmacSHA1");

					lengthOfMessage = dis.readInt();
					tmpBufferArray = new byte[lengthOfMessage];
					dis.readFully(tmpBufferArray);

					if(Arrays.equals(tmpBufferArray, keyedHash))
						System.out.println("Hashes Matched :)");
					else
						System.err.println("Hashes did not match!!");
				}
				// message 3 reading ended

				//message 4
				//read keyed hash from client
				if(!isOldSessionResumed)
				{
					lengthOfMessage = dis.readInt();
					beforeHash += String.valueOf(lengthOfMessage);
					System.out.println("Length of client's keyed hash:"+lengthOfMessage);
					tmpBufferArray = new byte[lengthOfMessage];
					dis.readFully(tmpBufferArray);
					beforeHash += Util.byteArrayToHexString(tmpBufferArray);
					byte [] keyedHashFromClient = tmpBufferArray;

					System.out.println("Shahash:"+Util.byteArrayToHexString(shaHashed));
					System.out.println("hash from client:"+Util.byteArrayToHexString(keyedHashFromClient));
					//message end

					if(Arrays.equals(keyedHashFromClient,shaHashed))
						System.out.println("keyed hash matched :) :)");
					else
						System.out.println("hashes don't match!");

					//message 5 send keyed has to client
					shaHashed = Util.sha1(beforeHash,String.valueOf(gabModP), "HmacSHA1");
					System.out.println("Shahash calculated at Gateway 2nd time:"+Util.byteArrayToString(shaHashed));
					System.out.println("Length of keyed hash sent by me:"+ shaHashed.length);
					dos.writeInt(shaHashed.length);
					System.out.println("Sha being sent by me:"+Util.byteArrayToHexString(shaHashed));
					dos.write(shaHashed);
					//message end

				}
				//----------------end of message 4		



				//------------------------------------------------------Handshake part is done -----------------------------------------------------------------------

				createKeys(gabModP, rClient, rServer); //call the method that creates keys for the integrity and encryption

				//send the session key
				sessionId = Util.sha1(Util.byteArrayToHexString(secretKey), String.valueOf(gabModP), "HmacSHA256");
				System.out.println("Length of session Id:"+sessionId.length);
				System.out.println("Session id:"+Util.byteArrayToHexString(sessionId));

				byte[] encryptedSessionId = Util.encrypt(sessionId, serverEncryptionKey);
				System.out.println("Encrypted session id length:"+encryptedSessionId.length);
				dos.writeInt(encryptedSessionId.length);
				System.out.println("Encrypted Session id:"+Util.byteArrayToHexString(encryptedSessionId));
				dos.write(encryptedSessionId);

				//send the sha of the previous message
				shaHashed = Util.shaByte(Util.byteArrayToHexString(encryptedSessionId),serverIntegrityKey, "HmacSHA1");
				System.out.println("Shahash calculated at Gateway for the encrypted SessionInd:"+Util.byteArrayToHexString(shaHashed));
				System.out.println("Length of keyed hash sent:"+ shaHashed.length);
				dos.writeInt(shaHashed.length);
				System.out.println("Sha being sent:"+Util.byteArrayToHexString(shaHashed));
				dos.write(shaHashed);
				//Ended sending session key to client

				//Serialize the key
				String clientName = "Naveen";
				doSerialize(sessionId, clientName);
				//serialization done

				//let the data transfer begin
				dataTransfer(dos, dis, gabModP);
				
				

			}
			catch(EOFException e0)
			{
				System.err.println("Taking longer time to send/receive message... Timed out :(");
			}
			catch (Exception e)
			{
				e.printStackTrace();
			}
		}

		private void createKeys(long gabModP, long rClient, long rServer)
		{
			//Start to calculate secretKey
			try{
				String tmp = String.valueOf(gabModP) + String.valueOf(rClient) +String.valueOf(rServer);
				secretKey = Util.sha1(tmp, " ", "HmacSHA256");
				System.out.println("Secret Key generated:"+Util.byteArrayToHexString(secretKey));
				// ended secret key generated

				// Start finding encryption and integrity protection keys by using SHA512
				String seed = "vEhqO5svEalAg3pE7MBjmWyil2A=";
				clientEncryptionKey = Util.shaByte(seed, secretKey, "HmacSHA512");
				System.out.println("Client Encryption Key:"+Util.byteArrayToHexString(clientEncryptionKey));
				// ended finding encryption and integrity protection keys by using SHA512

				serverEncryptionKey = Util.shaByte(Util.byteArrayToHexString(clientEncryptionKey), secretKey, "HmacSHA512");
				System.out.println("Server Encryption Key:"+Util.byteArrayToHexString(serverEncryptionKey));

				clientIntegrityKey = Util.shaByte(Util.byteArrayToHexString(serverEncryptionKey), secretKey, "HmacSHA512");
				System.out.println("Client Integrity Key:"+Util.byteArrayToHexString(clientIntegrityKey));

				serverIntegrityKey = Util.shaByte(Util.byteArrayToHexString(clientIntegrityKey), secretKey, "HmacSHA512");
				System.out.println("Server Integrity Key:"+Util.byteArrayToHexString(serverIntegrityKey));

				System.out.println("Client encryption key is: " + Util.byteArrayToHexString(clientEncryptionKey));
			}catch(Exception e)
			{
				e.printStackTrace();
			}
		}

		private void dataTransfer(DataOutputStream dos, DataInputStream dis, long gabModP)
		{
			try{


				byte [] tmpBufferArray = null;
				int lengthOfMessage =0;
				int lengthOfTran =0;

				//read header
				byte tmpByte = dis.readByte();
				tmpByte = dis.readByte();
				tmpByte = dis.readByte();

				int lengthofFileName = dis.readInt();
				System.out.println("Length of fileName:"+lengthofFileName);
				tmpBufferArray = new byte[lengthofFileName];
				dis.readFully(tmpBufferArray);
				byte [] fileName = tmpBufferArray; 
				System.out.println("Filename:"+Util.byteArrayToString(fileName));

				String fileNameInHexString = Util.byteArrayToString(fileName);
				if(files.containsKey(fileNameInHexString))
				{
					System.err.println("Received same file before.. Ignoring this connection..");
				}
				else
				{
					System.out.println("This is a fresh file.. Adding to Hashmap..");
					files.put(fileNameInHexString, true);

					FileOutputStream outStream = new FileOutputStream("Picture.jpg");
					BufferedOutputStream bos = new BufferedOutputStream(outStream);

					Mac hmac = Mac.getInstance("HmacSHA1");
					SecretKeySpec secret = new SecretKeySpec(clientIntegrityKey,"HmacSHA1");
					hmac.init(secret);
					int justFlag =0;
					while((lengthOfTran = dis.readInt()) !=0 )
					{
						System.out.println("Length of Tran:"+lengthOfTran);
						tmpBufferArray = new byte [lengthOfTran];
						dis.readFully(tmpBufferArray);

						//make hmac of received data
						byte[] hmacOfReceivedData = hmac.doFinal(tmpBufferArray);
						//made hmac

						//read Hmac from client
						lengthOfMessage = dis.readInt();
						byte hmacBuffer[] = new byte [lengthOfMessage]; 
						dis.readFully(hmacBuffer);
						//hmac reading done from client

						justFlag++;
						if(Arrays.equals(hmacBuffer, hmacOfReceivedData))
						{
							byte [] decryptedBytes = Util.decrypt(tmpBufferArray, clientEncryptionKey);
							bos.write(decryptedBytes);
							System.out.println("Reading Chunk number: " + justFlag );
						}
						else
						{
							System.err.println("Chunk number:"+justFlag+" did not work.");
						}
					}
					System.out.println("File transfer complete!!");
					bos.close();
					
					//dos.writeInt(0);// sending flag message to client.
					//need to call Alice to send the data transfer to the real server
					Alice newConnection  = new Alice(false, fileNameInHexString);
					int returnCode = newConnection.connectToServer();
					if(returnCode == -1)
					{
						System.err.println("Error occured in communication between Gateway2 and Server");
					}
					else
					{
						System.out.println("Received Ack from Gateway2(Alice)");
						System.out.println("Sending Success Message to client");
						dos.writeInt(0);//sending ack to client to stop watch
					}
					
				}

			}
			catch(Exception e)
			{
				e.printStackTrace();
			}
			
		}
	}
}

