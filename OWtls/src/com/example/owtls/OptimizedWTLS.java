package com.example.owtls;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.sql.Date;
import java.util.Arrays;
import java.util.HashMap;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import android.annotation.TargetApi;
import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.database.ContentObserver;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.provider.MediaStore;
import android.provider.MediaStore.MediaColumns;
import android.text.method.ScrollingMovementMethod;
import android.util.Base64;
import android.util.Log;
import android.view.Menu;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.TextView;
import android.widget.Toast;
import android.widget.ToggleButton;


public class OptimizedWTLS extends Activity {

	//all the objects will go here
	//android application related
	ToggleButton optimizeToggle;
	TextView textConnectionDisplay;
	private PhotosObserver instUploadObserver = new PhotosObserver();
	private String saved;
	private Thread uploadThread;
	public static Context context;
	public static final String TAG_THREAD = "WTLS Thread";
	public static final String TAG_PhotoClass = "PhotoClass";
	public static final String TAG_WTLS = "SSL";
	public static final String TAG_Resume = "Session Resumed";
	public static String testString = "Test";
	long timeDiff;
	String messageTextView = "";
	
	//test, can be deleted
	//keep track of camera capture intent
	final int CAMERA_CAPTURE = 1;
	//captured picture uri
	private Uri picUri;

	//WTLS Related
	SecureRandom randomNumber = new SecureRandom();
	long g = 33677, p = 159197;

	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
		context = getApplicationContext();

		//flagOptimize shared preferences setting
		final SharedPreferences preferences = getApplicationContext().getSharedPreferences("WTLS", 0);
		final SharedPreferences.Editor editor = preferences.edit();
		if (preferences.getInt("flagOptimize", -1) == -1 ) {
			editor.putInt("flagOptimize",0).commit();
			Log.i("Preferences","flagOptimize is not set, so setting now");
		}
		if(preferences.getString("sessionID", "empty").equalsIgnoreCase("empty")) {
			Log.i("Preferences", "This is not set, setting it now");
			editor.putString("sessionID", "empty").commit();
		}
		if(preferences.getString("Connections", "empty").equalsIgnoreCase("")) {
			Log.i("Preferences", "This is not set, setting it now");
			editor.putString("messageTextView", "").commit();
		}

		//initializing the text view
		textConnectionDisplay = (TextView) findViewById(R.id.textConnectionDisplay);
		textConnectionDisplay.setMovementMethod(new ScrollingMovementMethod());
		//textConnectionDisplay.setText("Time will be displayed here!");

		//setting listener for toggle button
		optimizeToggle = (ToggleButton) findViewById(R.id.toggleButton1);
		optimizeToggle.setOnClickListener(new OnClickListener() {
			public void onClick(View v) {
				if(optimizeToggle.isChecked())
				{
					//Toast.makeText(getApplicationContext(), "The state is changed to on", Toast.LENGTH_LONG).show();
					//textConnectionDisplay.setText("Optimization is ON now");
					//flagOptimize = 1;				
					editor.putInt("flagOptimize", 1).commit();
					//Toast.makeText(getApplicationContext(), "inside set on", Toast.LENGTH_LONG).show();
				}
				else
				{
					//Toast.makeText(getApplicationContext(), "The state is changed to off", Toast.LENGTH_LONG).show();
					//textConnectionDisplay.setText("Optimization is OFF now");
					//flagOptimize = 0;
					editor.putInt("flagOptimize", 0).commit();
				}
			}
		});
		
		//onclick for the textview
		textConnectionDisplay.setOnClickListener(new OnClickListener() {
			
			public void onClick(View v) {
				//Toast.makeText(getApplicationContext(), "Content will be updated now", Toast.LENGTH_SHORT).show();
				String message = preferences.getString("Connections", "");
				textConnectionDisplay.setText(message);
				
			}
		});

		//commenting the code so that the issues may be solved :)
		//Registering for photo taken event
		/*this.getApplicationContext()
		.getContentResolver().registerContentObserver(
				MediaStore.Images.Media.EXTERNAL_CONTENT_URI, false,
				instUploadObserver);
		Log.d("INSTANT", "registered content observer");*/
	}

	/**
	 * This will be called when the camera button is clicked
	 * @param view
	 */
	public void startCamera(View view) {
		System.out.println("Clicked the camera button");
		//define the file-name to save photo taken by Camera activity
		try {
		    //use standard intent to capture an image
		    Intent captureIntent = new Intent(MediaStore.ACTION_IMAGE_CAPTURE);
		    //we will handle the returned data in onActivityResult
		    startActivityForResult(captureIntent, CAMERA_CAPTURE);
		} catch(ActivityNotFoundException anfe){
		    //display an error message
		    String errorMessage = "Whoops - your device doesn't support capturing images!";
		    Toast toast = Toast.makeText(this, errorMessage, Toast.LENGTH_SHORT);
		    toast.show();
		}

		
	}
	
	/**
	 * This is for on result after taking the picture
	 */
	protected void onActivityResult(int requestCode, int resultCode, Intent data) {
		System.out.println("Inside on activity result");
	    if (resultCode == RESULT_OK) {
	    	Log.i("OnResult", "RESULT_OK");
	    	if(requestCode == CAMERA_CAPTURE){
	    		Log.i("OnResult", "Inside CAMERA_CAPTURE");
	    		picUri = data.getData();
	    		System.out.println(picUri.getPath() + " is the URI of the picture taken");
	    		Media media = readFromMediaStore(getApplicationContext(), picUri);
	    		String fileName  = media.file.getName();
				saved = "I detected " + fileName + " and it is in the path: " + media.file.getPath();	
				System.out.println("This is what I got: " + saved);
				
				messageTextView = "";
				//starting the thread
				uploadThread = new MyThread();
				uploadThread.start();
				Log.v("OnResult", "Thread started from here");	
	    	}
	    }
	}
	
	
	@Override
	protected void onDestroy() {
		super.onDestroy();
		//this.getContentResolver().unregisterContentObserver(instUploadObserver);
		//Log.d("In OnDestroy", "Unregistering");
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		getMenuInflater().inflate(R.menu.activity_main, menu);
		return true;
	}

	/**
	 * This is the class which is supposed to do the WTLS part
	 */
	public class MyThread extends Thread {

		//global variables for this thread
		byte[] eKeyClient, eKeyServer, iKeyClient, iKeyServer, secretKey;
		Socket socket = null;
		ByteBuffer buffer;
		InputStream in = null;
		DataInputStream dis = null;
		OutputStream out = null;
		DataOutputStream dos = null;
		// certificate objects
		CertificateFactory certificateFactory = null;
		InputStream certificateStream;
		X509Certificate aliceCertificate = null;
		RSAPrivateKey alicePrivateKey = null;
		X509Certificate bobCertificate = null;
		RSAPublicKey bobPublicKey = null;
		String beforeHash = "";
		int lengthOfMessage =0;
		byte [] tmpBufferArray = null;
		public String ip_Address = "192.168.137.232";
		//public String ip_Address = "192.168.2.5";
		long timeBefore;

		SharedPreferences preferences = getApplicationContext().getSharedPreferences("WTLS", 0);
		final SharedPreferences.Editor editor_storage = preferences.edit();
		
		@Override
		@TargetApi(14)
		public void run() {
			try {
				// WTLS part should be implemented here
				Log.i(TAG_THREAD, "WTLS should start now!");
				//global variables for this thread

				/**
				 * 1. First check the flag.
				 * 2. Based on the flag, check is another session is present or not.
				 */
				
				int flagOpt = preferences.getInt("flagOptimize", -1);
				System.out.println("This is the flag obtained " + flagOpt);
				Log.i(TAG_THREAD, "Flag obtained is: " +flagOpt);

				timeBefore = System.currentTimeMillis();
				if(flagOpt == 0) {
					//This is the code for SSL initiation from start
					//may be call a method, so that that from else part we can call easily. 
					doSSL(editor_storage);
					System.out.println(preferences.getString("sessionID", "FO"));
				} else {
					//This is the session resumption code.
					//Check if session already exists, else do from beginning.
					//i.e, call the method which does the full handshake.
					//IF session is present, get its details, and start the session.
					String sessID = preferences.getString("sessionID", "0");
					if(sessID.equalsIgnoreCase("empty")) {
						System.out.println("Session id is not available, will be initialising from first, got this " + sessID);
						doSSL(editor_storage);
					} else {
						System.out.println("Session id already present, will be staring from middle, this is the session id: " + sessID);
						doSSLResumption(editor_storage, sessID);
					}
				}

			} finally {

			}
		}

		/**
		 * This method does the entire 
		 * @param editor_storage 
		 */
		private void doSSL(Editor editor_storage) {

			String executionPath = Util.getCurrentExecutionPath();
			System.out.println(executionPath);
			InetAddress host = null;
			try
			{
				host = InetAddress.getLocalHost();
			} 
			catch (UnknownHostException e2)
			{
				e2.printStackTrace();
				return;
			}

			// Open socket to Bob.. Bob is a Server
			try
			{
				socket = new Socket(ip_Address, Util.PORT_OF_BOB);
				//System.out.println("hi");
			}
			catch (UnknownHostException e1)
			{
				e1.printStackTrace();
			}
			catch (IOException e1)
			{
				e1.printStackTrace();
			}
			catch(Exception e) {
				System.out.println("Some other exceptions");
				e.printStackTrace();
			}
			//connection established
			Log.i(TAG_WTLS, "Connection established");

			//build SHA
			MessageDigest sha1 = null;
			try {
				sha1 = MessageDigest.getInstance("SHA1");
			}catch (NoSuchAlgorithmException e2)
			{
				e2.printStackTrace();
			}
			//built SHA
			Log.i(TAG_WTLS,"SHA Initialised");

			try {
				in = socket.getInputStream();

				dis = new DataInputStream(in);
				out = socket.getOutputStream();
				dos = new DataOutputStream(out);

				//wtls information .. 
				//sendInfo();

				//sending things for a new connection. Sending Zero.
				dos.writeInt(0);
				//getting things for first message
				long rAlice = randomNumber.nextLong();
				String rAliceStr = String.valueOf(rAlice);
				String ciphersToUse = "SSL_RSA_WITH_3DES_EDE_CBC_SHA1";

				String toBeSentMessage1 = rAliceStr + "," + ciphersToUse;
				System.out.println(toBeSentMessage1);
				dos.writeInt(toBeSentMessage1.getBytes().length);
				dos.write(toBeSentMessage1.getBytes());
				//saving hashes for sending hash of messages
				beforeHash += String.valueOf(toBeSentMessage1.getBytes().length);
				System.out.println(Util.byteArrayToHexString(beforeHash.getBytes()) + " hash1");
				beforeHash += toBeSentMessage1;
				System.out.println(Util.byteArrayToHexString(beforeHash.getBytes()) + " hash2");

				//receiving the second message
				//getting Random number
				Long rServer = dis.readLong();
				System.out.println("The nonce Rserver is " + rServer);

				beforeHash += String.valueOf(rServer);
				System.out.println(Util.byteArrayToHexString(beforeHash.getBytes()) + " hash3");

				//getting length of certificate
				lengthOfMessage = dis.readInt();
				tmpBufferArray = new byte [lengthOfMessage];
				dis.readFully(tmpBufferArray);

				/*buffer = ByteBuffer.wrap(tmpBufferArray);
					//gets the 0,len of the message
					buffer.get(tmpBufferArray,0,lengthOfMessage);*/

				//constructing the certificate
				String encodedCertificateOfBob = Util.byteArrayToString(tmpBufferArray);

				certificateStream = new ByteArrayInputStream(tmpBufferArray);
				certificateFactory = CertificateFactory.getInstance("X.509");
				bobCertificate = (X509Certificate)certificateFactory.generateCertificate(certificateStream);
				bobPublicKey = (RSAPublicKey)bobCertificate.getPublicKey();
				System.out.print("\n\n[Alice finds out Bob's public key]"
						+"\n\t\t Bob's public key="+bobPublicKey.toString());
				certificateStream.close();

				Long gbmodp = dis.readLong();
				System.out.println("The g^b modp sent is " + gbmodp);

				//saving the values for hashes
				beforeHash = beforeHash + String.valueOf(lengthOfMessage);
				System.out.println(Util.byteArrayToHexString(beforeHash.getBytes()) + " Hash 4");
				//beforeHash += Base64.encode(tmpBufferArray,0); 
				//System.out.println(Util.byteArrayToHexString(beforeHash.getBytes()) + " Hash 5");

				sha1.update(ByteBuffer.allocate(tmpBufferArray.length).put(tmpBufferArray).array());
				byte [] keyedHash = sha1.digest();
				beforeHash += Util.byteArrayToHexString(keyedHash);
				System.out.println("Hash for 5th part is "+Util.byteArrayToHexString(keyedHash));				

				beforeHash += String.valueOf(gbmodp); 
				System.out.println(Util.byteArrayToHexString(beforeHash.getBytes()) + " Hash 6");

				int mySecretA = randomNumber.nextInt();
				Long gamodp = Util.pow(Math.abs(mySecretA),g);
				System.out.println(gamodp + " is gamodp");

				// read the certificate from file
				String pathToSD = Environment.getExternalStorageDirectory().getAbsolutePath();
				System.out.println(pathToSD + " is the path to sdcard");
				certificateStream = new FileInputStream(pathToSD+"/OWtls/alice.der");
				System.out.println("Success pola.");
				certificateFactory = CertificateFactory.getInstance("X.509");
				aliceCertificate = (X509Certificate)certificateFactory.generateCertificate(certificateStream);
				certificateStream.close();

				File f = new File(pathToSD+"/OWtls/alice.key8");
				FileInputStream fis = new FileInputStream(f);
				DataInputStream disFile = new DataInputStream(fis);
				byte[] keyBytes = new byte[(int)f.length()];
				disFile.readFully(keyBytes);
				disFile.close();
				// done with reading certificate from file...

				PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
				KeyFactory kf = KeyFactory.getInstance("RSA");
				alicePrivateKey = (RSAPrivateKey) kf.generatePrivate(spec);

				byte[] encodedCertificate = aliceCertificate.getEncoded();
				System.out.println("Encoded certificcate is " + Util.byteArrayToHexString(encodedCertificate));
				int encodedCertLength = encodedCertificate.length;
				System.out.println(encodedCertLength + " is the length of encodedCertLength");

				/*String base64EncodedCert = Base64.encodeToString(encodedCertificate, 0);
				System.out.println("Base64 encoded certificate is " + base64EncodedCert);
				int lengthOfBase64EncodedCert = base64EncodedCert.length();
				System.out.println("Base64 encoded cert length is" + lengthOfBase64EncodedCert);*/

				//byte[] compressedCertificate = Util.compress(encodedCertificate);

				//byte[] plainTextMessage = ByteBuffer.allocate(encodedCertLength + 16).put(encodedCertificate).putLong(gamodp).putLong(gbmodp).array();
				//System.out.println(plainTextMessage + " is ths plaintextmessage");
				Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
				System.out.println("After cipher getinstance");
				cipher.init(Cipher.ENCRYPT_MODE, bobPublicKey);
				System.out.println("After cipher init");
				byte[] message3Encrypted = cipher.doFinal(ByteBuffer.allocate(16).putLong(gamodp).putLong(gbmodp).array());						

				int encryptedMessage3Len = message3Encrypted.length;

				//sending length for message3, with two rands
				dos.writeInt(encryptedMessage3Len);
				System.out.println(encryptedMessage3Len);
				dos.write(message3Encrypted);
				System.out.println(Util.byteArrayToHexString(message3Encrypted) + " is the message Encrypted (message 3 i need to sent");

				beforeHash = beforeHash + String.valueOf(encryptedMessage3Len); 
				System.out.println(Util.byteArrayToHexString(beforeHash.getBytes()) + " hash 7");
				beforeHash += Util.byteArrayToHexString(message3Encrypted);
				System.out.println(Util.byteArrayToHexString(beforeHash.getBytes()) + " hash 8");

				Long gabmodp = Util.pow(Math.abs(mySecretA), gbmodp);
				System.out.println(gabmodp + " is the gabmodp");
				byte[] shaHash = Util.sha1(beforeHash, String.valueOf(gabmodp), "HmacSHA1");


				System.out.println(Util.byteArrayToString(shaHash) + " is ths hash at client");
				//System.out.println();

				System.out.println(mySecretA + " is mysecret");

				System.out.println(Util.byteArrayToHexString(shaHash) + " is the hash at this side");

				lengthOfMessage = shaHash.length;
				System.out.println("MEssage llength I sent is" + lengthOfMessage);
				dos.writeInt(lengthOfMessage);
				//sending message
				System.out.println("Hash sent to other side in message3 is :" + Util.byteArrayToHexString(shaHash));
				dos.write(shaHash);

				beforeHash += String.valueOf(lengthOfMessage) +  Util.byteArrayToHexString(shaHash);
				Log.i(TAG_WTLS, beforeHash + " is after sending message3");

				//sending keyed hash, first length
				lengthOfMessage = dis.readInt();
				System.out.println("Message4 length is " + lengthOfMessage);
				tmpBufferArray = new byte [lengthOfMessage];
				dis.readFully(tmpBufferArray);
				System.out.println("Hash obtained in message 4 is " + Util.byteArrayToHexString(tmpBufferArray));
				shaHash = Util.sha1(beforeHash, String.valueOf(gabmodp), "HmacSHA1");
				if(Arrays.equals(shaHash, tmpBufferArray)) {
					System.out.println("Success");
				} else {
					System.out.println("Hashes do not match :( :( :(");
					System.out.println(Util.byteArrayToHexString(shaHash) + " is what I have, yours is at the top");
				}


				//-----------------------------------------------------------Handshake Phase Done-----------------------------------------------------------------			

				timeDiff = System.currentTimeMillis() - timeBefore; 
				System.out.println("Handshake happenend in " + timeDiff + " milli seconds");
				messageTextView += "Handshake happenend in " + timeDiff + " milli seconds \n";
				System.out.println(messageTextView + " is the message text view");
				
				//create keys
				createKeys(gabmodp, rAlice, rServer);

				//getting the session id from server for session resumption. This is the implementation efficient and optimized WTLS
				lengthOfMessage = dis.readInt();
				System.out.println("Length of the encrypted session id sent is" + lengthOfMessage);


				tmpBufferArray = new byte[lengthOfMessage];
				dis.readFully(tmpBufferArray);
				byte[] tmptmpBufferArray = tmpBufferArray;
				//decrypt the session id
				byte[] sessID = Util.decrypt(tmpBufferArray, eKeyServer);
				String sessIDStr = Util.byteArrayToString(sessID);
				String base64EncodedSessionId  =Base64.encodeToString(sessID, 0);
				System.out.println("Session ID ontained encrypted is " + Util.byteArrayToString(tmpBufferArray));
				System.out.println("Session id sent is: " + sessIDStr);
				System.out.println(base64EncodedSessionId + " is the base64 encoded");

				//need to check the hashes now and if its correct, then store into session, else break and print error!

				lengthOfMessage = dis.readInt();
				System.out.println("Length of the hash sent for session id is" + lengthOfMessage);

				tmpBufferArray = new byte[lengthOfMessage];
				dis.readFully(tmpBufferArray);
				byte[] hashThisSide = Util.shaByte(Util.byteArrayToHexString(tmptmpBufferArray), iKeyServer, "HmacSHA1");
				System.out.println("This is the hash at my side of encrypted session id: " + Util.byteArrayToHexString(hashThisSide));

				if(Arrays.equals(hashThisSide, tmpBufferArray)) {
					System.out.println("Success, session id matched, stored in application context, this is session id stored:" + sessIDStr);
					//storing the session id in application memory to restart it.
					editor_storage.putString("sessionID", base64EncodedSessionId).commit();
				} else {
					System.out.println("Hashes do not match :( :( :(");
					System.out.println(Util.byteArrayToHexString(tmpBufferArray) + " is the hash gateway sent me");
				}

				//calling data transfer method
				dataTransfer(dos, dis, gabmodp);

				catchTime(dis);
				dos.close();
				dis.close();
				socket.close();
			}	catch (Exception e) {
				e.printStackTrace();
			}
			
		}

		/**
		 * This method is to catch time.
		 * @param dis2 
		 */
		private void catchTime(DataInputStream dis2) {
			// TODO Auto-generated method stub
			try {
				//reading from gateway
				//int ack = dis2.readInt();
				long timeAfter = System.currentTimeMillis();
				timeDiff = (timeAfter - timeBefore) / 1000;
				System.out.println(timeBefore + ": timebefore");
				System.out.println("Got the ack from Gateway, time taken is seconds: " + timeDiff);
				messageTextView += "Transferred to gateway in " + timeDiff + " seconds\n";
				
				int ack = dis2.readInt();
				timeAfter = System.currentTimeMillis();
				timeDiff = (timeAfter - timeBefore) / 1000;
				System.out.println("Got ack from gateway that it has reached server, time taken in seconds:" + timeDiff);
				messageTextView += "Transferred to server in " + timeDiff + " seconds\n ************************\n";
				
				//updating shared preferences
				String message = preferences.getString("Connections", "");
				editor_storage.putString("Connections", messageTextView + message).commit();
				/*Thread update = new updateUIThread();
				update.start();
				System.out.println("Thread started");*/
				
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
		}

		
		/*public class updateUIThread extends Thread {
			//this is for updating the UI thread with the details
			public void run () {
			OptimizedWTLS.this.runOnUiThread(new Runnable() {

		        public void run() {
		            Toast.makeText(OptimizedWTLS.this, "This is Toast!!!", Toast.LENGTH_SHORT).show();
		            System.out.println("This is working!");
		            TextView t = (TextView)findViewById(R.id.textConnectionDisplay);
					//t.setText("Got the ack from Gateway, time taken is seconds: " + timeDiff + " Got ack from gateway that it has reached server, time taken in seconds:" + timeDiff);
		            //String before = t.getText().toString();
					t.setText("It took " + timeDiff + " seconds to reach gateway and " + timeDiff2 + " seconds to reach the server");

		        }
		    });
			
			}
		}*/
	
		
	
		
	
		/**
		 * This method sends information to gateway
		 */
		private void sendInfo() {

			//getting picture from media store
			Media media = readFromMediaStore(getApplicationContext(),
					MediaStore.Images.Media.EXTERNAL_CONTENT_URI);
			String filename = media.file.getName();
			byte[] fileNameBytes = filename.getBytes();
			try {
				dos.writeInt(fileNameBytes.length);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			try {
				dos.write(fileNameBytes);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		/**
		 * This method is for session resumption ssl
		 * @param editor_storage
		 * @param sessID 
		 */
		private void doSSLResumption(Editor editor_storage, String sessID) {

			beforeHash = "";
			InetAddress host = null;
			try
			{
				host = InetAddress.getLocalHost();
			} 
			catch (UnknownHostException e2)
			{
				e2.printStackTrace();
				return;
			}

			// Open socket to Bob.. Bob is a Server
			try
			{
				socket = new Socket(ip_Address, Util.PORT_OF_BOB);
				System.out.println("hi");
			}
			catch (UnknownHostException e1)
			{
				e1.printStackTrace();
			}
			catch (IOException e1)
			{
				e1.printStackTrace();
			}
			catch(Exception e) {
				System.out.println("Some other exceptions");
				e.printStackTrace();
			}
			//connection established
			Log.i(TAG_WTLS, "Connection established");

			//build SHA
			MessageDigest sha1 = null;
			try {
				sha1 = MessageDigest.getInstance("SHA1");
			}catch (NoSuchAlgorithmException e2)
			{
				e2.printStackTrace();
			}
			//built SHA
			Log.i(TAG_WTLS,"SHA Initialised");

			try {
				in = socket.getInputStream();

				dis = new DataInputStream(in);
				out = socket.getOutputStream();
				dos = new DataOutputStream(out);

				//important
				//sendInfo();
				//sending things for the session resumption, sending one
				dos.writeInt(1);

				//need to send the first message, send session id, Ralice, gamodp
				//sessID is the session.
				long rAlice = randomNumber.nextLong();
				String rAliceStr = String.valueOf(rAlice);
				Log.i(TAG_Resume, "rAlice is " + rAliceStr);

				int mySecretA = randomNumber.nextInt();
				Long gamodp = Util.pow(Math.abs(mySecretA),g);
				System.out.println(gamodp + " is gamodp");
				Log.i(TAG_Resume, "gamodp is " + gamodp);

				String firstMessageToBeSent = sessID + "," + rAliceStr + "," + String.valueOf(gamodp);
				dos.writeInt(firstMessageToBeSent.length());
				System.out.println("First message length is " + firstMessageToBeSent.length());
				//writing the message now
				byte[] firstMessageToBeSentBytes = firstMessageToBeSent.getBytes();
				System.out.println("The first message sent in bytes is " + Util.byteArrayToString(firstMessageToBeSentBytes));
				dos.write(firstMessageToBeSent.getBytes());
				beforeHash = firstMessageToBeSent.length() + firstMessageToBeSent;

				//getting the second message
				lengthOfMessage = dis.readInt();
				if (lengthOfMessage == -1) {
					//System.out.println("Session id not matched, opening a new connection");
					Log.i(TAG_Resume, "Session id not matched, opening a new connection");
					doSSL(editor_storage);
				}
				else {
					tmpBufferArray = new byte[lengthOfMessage];
					dis.readFully(tmpBufferArray);

					String recvdMessage = Util.byteArrayToString(tmpBufferArray);
					String[] recvdStringSplit = recvdMessage.split(",");

					//reading r server
					Long rServer = Long.parseLong(recvdStringSplit[0]);
					Log.i(TAG_Resume, "Thr Rserver obtained is " + rServer);

					Long gbmodp = Long.parseLong(recvdStringSplit[1]);
					Log.i(TAG_Resume, "Thr gbmodp obtained is " + gbmodp);

					//getting the encoded bytes of hash now.
					String hashThatSide = recvdStringSplit[2];

					Long gabmodp = Util.pow(Math.abs(mySecretA), gbmodp);
					Log.i(TAG_Resume, "Thr gabmodp obtained is " + gabmodp);

					//finding the keyed hash now
					byte[] keyedHashThisSide = Util.sha1(beforeHash, String.valueOf(gabmodp), "HmacSHA1");
					String hashThisSide = Base64.encodeToString(keyedHashThisSide, 0);

					byte[] keyedHashThatSide = Base64.decode(hashThatSide, 0);

					if(Arrays.equals(keyedHashThisSide, keyedHashThatSide)) {
						Log.i(TAG_Resume, "Hashes match");
					} else {
						System.out.println("Hashes do not match, hashthisside is " + hashThisSide + " that side is " + hashThatSide);
						return;
					}

					//need to send the message to other side, keyed hash
					//create hash and send 'em
					beforeHash += String.valueOf(lengthOfMessage);
					beforeHash += Util.byteArrayToString(tmpBufferArray);
					keyedHashThisSide = Util.sha1(beforeHash, String.valueOf(gabmodp), "HmacSHA1");
					lengthOfMessage = keyedHashThisSide.length;
					dos.writeInt(lengthOfMessage);
					System.out.println("Length of the meessage3: keyed hash is" + lengthOfMessage);

					//writing the bytes into stream, keyed hash
					dos.write(keyedHashThisSide);
					
					timeDiff = System.currentTimeMillis() - timeBefore; 
					System.out.println("Optimized Handshake happenend in " + timeDiff + " milli seconds");
					messageTextView += "Optimized Handshake happenend in " + timeDiff + " milli seconds \n";

					//create keys
					createKeys(gabmodp, rAlice, rServer);

					//getting the session id from server for session resumption. This is the implementation efficient and optimized WTLS
					lengthOfMessage = dis.readInt();
					System.out.println("Length of the encrypted session id sent is" + lengthOfMessage);


					tmpBufferArray = new byte[lengthOfMessage];
					dis.readFully(tmpBufferArray);
					byte[] tmptmpBufferArray = tmpBufferArray;
					//decrypt the session id
					byte[] sessIDArr = Util.decrypt(tmpBufferArray, eKeyServer);
					String sessIDStr = Util.byteArrayToString(sessIDArr);
					String base64EncodedSessionId  =Base64.encodeToString(sessIDArr, 0);
					System.out.println("Session ID ontained encrypted is " + Util.byteArrayToString(tmpBufferArray));
					System.out.println("Session id sent is: " + sessIDStr);
					System.out.println(base64EncodedSessionId + " is the base64 encoded");

					//need to check the hashes now and if its correct, then store into session, else break and print error!

					lengthOfMessage = dis.readInt();
					System.out.println("Length of the hash sent for session id is" + lengthOfMessage);

					tmpBufferArray = new byte[lengthOfMessage];
					dis.readFully(tmpBufferArray);
					byte[] hashThisSideArr = Util.shaByte(Util.byteArrayToHexString(tmptmpBufferArray), iKeyServer, "HmacSHA1");
					System.out.println("This is the hash at my side of encrypted session id: " + Util.byteArrayToHexString(hashThisSideArr));

					if(Arrays.equals(hashThisSideArr, tmpBufferArray)) {
						System.out.println("Success, session id matched, stored in application context, this is session id stored:" + sessIDStr);
						//storing the session id in application memory to restart it.
						editor_storage.putString("sessionID", base64EncodedSessionId).commit();
					} else {
						System.out.println("Hashes do not match :( :( :(");
						System.out.println(Util.byteArrayToHexString(tmpBufferArray) + " is the hash gateway sent me");
					}

					//calling data transfer method
					dataTransfer(dos, dis, gabmodp);

					catchTime(dis);
					dos.close();
					dis.close();
					socket.close();
				}	



			} catch (Exception e) {
				e.printStackTrace();
			}

			
		}


		/**
		 * This is the method to create the keys
		 * @param gabmodp is the gabmodp obtained from the Diffie Hellman exchange
		 * @param rAlice is the random number of client sent to server
		 * @param rServer is the random number sent by server
		 */
		private void createKeys(Long gabmodp, long rAlice, Long rServer) {
			//calculating s now
			try {
				String toBeHashed = String.valueOf(gabmodp) + String.valueOf(rAlice) + String.valueOf(rServer);
				secretKey = Util.sha1(toBeHashed, " ","HmacSHA256");
				System.out.println("Secret key is " + Util.byteArrayToHexString(secretKey));

				//now finding auth keys and encryption keys using secret key as key using SHA512
				eKeyClient = Util.shaByte("vEhqO5svEalAg3pE7MBjmWyil2A=", secretKey,"HmacSHA512");
				System.out.println("Encrypted key used for client is " + Util.byteArrayToHexString(eKeyClient));

				eKeyServer = Util.shaByte(Util.byteArrayToHexString(eKeyClient), secretKey,"HmacSHA512");
				System.out.println("Encrypted key used for server is " + Util.byteArrayToHexString(eKeyServer));

				iKeyClient = Util.shaByte(Util.byteArrayToHexString(eKeyServer), secretKey,"HmacSHA512");
				System.out.println("Integrity key used for client is " + Util.byteArrayToHexString(iKeyClient));

				iKeyServer = Util.shaByte(Util.byteArrayToHexString(iKeyClient), secretKey,"HmacSHA512");
				System.out.println("Encrypted key used for server is " + Util.byteArrayToHexString(iKeyServer));
			} catch(Exception e) {

			}
		}

		/**
		 * This is for data transfer
		 * @param dos
		 * @param dis
		 * @param gabmodp
		 */
		private void dataTransfer(DataOutputStream dos, DataInputStream dis, Long gabmodp) {

			try{				


				dos.write(0x18);//message type to close data
				dos.write(0x01);//major version number
				dos.write(0x00);//minor version number


				//getting picture from media store
				Media media = readFromMediaStore(getApplicationContext(),
						MediaStore.Images.Media.EXTERNAL_CONTENT_URI);
				String path = media.file.getAbsolutePath();
				System.out.println("This is the path " + path);
				File toBeSentPic = new File(path);
				System.out.println("Got the file name " + media.file.getName());
				//tmpBufferArray = testString.getBytes();

				//code added by Naveen to split the file
				BufferedInputStream bis = new BufferedInputStream(new FileInputStream(toBeSentPic));
				long fileSize = toBeSentPic.length();
				System.out.println("File size is " + fileSize);

				/*tmpBufferArray = Util.getBytesFromFile(f);

				byte [] encryptedToTransfer = Util.encrypt(tmpBufferArray, eKeyClient);

				byte[] dummy = Util.encrypt(secretKey, eKeyClient);
				//writing length
				dos.writeInt(dummy.length);

				System.out.println("Lenfggth of transfer is " + dummy.length);
				//writing encrypted data
				dos.write(dummy);*/

				//init code
				Mac hmac = Mac.getInstance("HmacSHA1");
				SecretKeySpec secret = new SecretKeySpec(iKeyClient,"HmacSHA1");
				hmac.init(secret);

				//code for splitting bytes
				int completed = 0;
				int step = 1048576;
				int i_seq = 0;
				byte[] bufferSmall = new byte[step];
				System.out.println("Before while loop");
				System.out.println("Android Client encryption key is: " + Util.byteArrayToHexString(eKeyClient));

				dos.writeInt(media.file.getName().getBytes().length);
				System.out.println("File Name Length is " + media.file.getName().getBytes().length);
				dos.write(media.file.getName().getBytes("UTF-8"));
				//splitting the file and sending.
				while (completed <= fileSize) {
					//System.out.println(completed + "  " + step);
					if((completed + step) > fileSize) {
						step = (int) (fileSize - completed);
						bufferSmall = new byte[step];
						//System.out.println(step + "  is the Size");
					}
					bis.read(bufferSmall, 0, step);
					System.out.println("Read part " + i_seq);
					byte[] encryptedToTransfer = Util.encrypt(bufferSmall, eKeyClient);
					System.out.println("Encrypted I guess :" + encryptedToTransfer.length);
					//need to send now, length first and message second
					dos.writeInt(encryptedToTransfer.length);
					dos.write(encryptedToTransfer);
					System.out.println("Sent part: " + i_seq);

					//calculate hmac of encrypted data 
					byte[] digestCalculatedFromEncryptedFile = hmac.doFinal(encryptedToTransfer);

					//write Hmac length
					dos.writeInt(digestCalculatedFromEncryptedFile.length);
					//write hmac
					dos.write(digestCalculatedFromEncryptedFile);

					i_seq++;
					completed += 1048576;
				}

				dos.writeInt(0);

				System.out.println("End of the while loop which is supposed to send the file");




				//actual code from Praful, which has been commented
				/*tmpBufferArray = Util.getBytesFromFile(toBeSentPic);
				System.out.println("This is the file bytes in hex string \n" + Util.byteArrayToHexString(tmpBufferArray));

				byte [] encryptedToTransfer = Util.encrypt(tmpBufferArray, bobEncryptionKey);
				System.out.println("I do not think this will work");

				System.out.print("\n [Bob prints string]"+Util.byteArrayToHexString(tmpBufferArray));
				System.out.print("\n\t Encrypted msg:"+Util.byteArrayToHexString(encryptedToTransfer));
				dos.writeInt(encryptedToTransfer.length);
				dos.write(encryptedToTransfer); */
			}
			catch(Exception e) {
				e.printStackTrace();
			}

		}
	}

	/*// Save the thread
	@Override
	public Object onRetainNonConfigurationInstance() {
		return uploadThread;
	}*/

	/**
	 * class photoObserver
	 * This will get called when a picture is clicked using the camera
	 */
	class PhotosObserver extends ContentObserver {

		//this is a file name which will be saved whenever photo is taken, so that
		//repetition is not done
		String oldFileName = "";
		HashMap<String, Boolean> files = new HashMap<String, Boolean>();
		public PhotosObserver() {
			super(null);
		}

		@Override
		public void onChange(boolean selfChange) {
			super.onChange(selfChange);
			//starting the thread for wtls
			/*uploadThread = (Thread) getLastNonConfigurationInstance();
		    if (uploadThread != null && uploadThread.isAlive()) {
		      Log.v(TAG_PhotoClass, "Already another thread is running, anyways will be starting a new thread");
		    }*/

			//getting the media
			Log.i(TAG_PhotoClass, "Sending the picture now" + new java.util.Date());
			Media media = readFromMediaStore(getApplicationContext(),
					MediaStore.Images.Media.EXTERNAL_CONTENT_URI);
			String fileName  = media.file.getName();
			saved = "I detected " + fileName + " and it is in the path: " + media.file.getPath();
			Log.d(TAG_PhotoClass, "detected camera event" + saved);

			//starting the thread to file transfer using ssl
			//testString = "may be used for image objects";

			if(files.containsKey(fileName))
			{
				System.err.println("Received same file before.. Ignoring this connection..");
			} else {
				files.put(fileName, true);
				System.out.println("Old File name is " + oldFileName + " and new file name is " + fileName);
				oldFileName = fileName;
				//if(uploadThread.isAlive()) {
					uploadThread = new MyThread();
					uploadThread.start();
					Log.v(TAG_PhotoClass, "Thread started from here");	
				//} else {
					//System.out.println("Thread has started already, please wait!");
				//}
				
			}

		}

		@Override
		public boolean deliverSelfNotifications() {
			return true;
		}
	}

	private Media readFromMediaStore(Context context, Uri uri) {
		Cursor cursor = context.getContentResolver().query(uri, null, null,
				null, "date_added DESC");
		Media media = null;
		if (cursor.moveToNext()) {
			int dataColumn = cursor.getColumnIndexOrThrow(MediaColumns.DATA);
			String filePath = cursor.getString(dataColumn);
			int mimeTypeColumn = cursor
					.getColumnIndexOrThrow(MediaColumns.MIME_TYPE);

			String mimeType = cursor.getString(mimeTypeColumn);
			media = new Media(new File(filePath), mimeType);
		}
		cursor.close();
		return media;
	}

	/**
	 * This is the class Media which will store and give the details of the file.
	 * @author Naveen
	 *
	 */
	private class Media {
		private File file;
		@SuppressWarnings("unused")
		private String type;

		public Media(File file, String type) {
			this.file = file;
			this.type = type;
		}

		public String getType() {
			return type;
		}

		public File getFile() {
			return file;
		}
	}

}


