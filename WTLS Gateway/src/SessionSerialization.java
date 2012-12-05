import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;

class Session implements Serializable{

	byte [] sessionKey;
	String clientName;

	public byte[] getSessionKey() {
		return sessionKey;
	}

	public void setSessionKey(byte[] sessionKey) {
		this.sessionKey = sessionKey;
	}

	public String getClientName() {
		return clientName;
	}

	public void setClientName(String clientName) {
		this.clientName = clientName;
	}

	Session(byte[] b, String name)
	{
		this.sessionKey = b;
		this.clientName = name;
	}
}	

public class SessionSerialization{

	final String serDirectory ="Ser";
	String keyString = "PrafullGateway";
	byte [] key = keyString.getBytes();

	public void serialize(Session s)
	{
		try {

			System.out.println("Serialize Session Key:"+Util.byteArrayToHexString(s.sessionKey));

			byte [] fileNameByteArray = Util.shaByte(Util.byteArrayToHexString(s.sessionKey), key, "HmacSHA1");
			FileOutputStream fs = new FileOutputStream(serDirectory+"/"+Util.byteArrayToHexString(fileNameByteArray)+".ser");
			ObjectOutputStream os = new ObjectOutputStream(fs);
			os.writeObject(s); // 3
			os.close();
		} catch (Exception e)
		{
			e.printStackTrace(); 
		}
	}

	public Session deserialize(byte[] sessionId)
	{
		Session s = null;

		byte [] fileNameByteArray;
		try {
			System.out.println("Deerialize Session Key:"+Util.byteArrayToHexString(sessionId));

			fileNameByteArray= Util.shaByte(Util.byteArrayToHexString(sessionId), key, "HmacSHA1");
			FileInputStream fis = new FileInputStream(serDirectory+"/"+Util.byteArrayToHexString(fileNameByteArray)+".ser");
			ObjectInputStream ois = new ObjectInputStream(fis);
			s = (Session) ois.readObject(); // 4
			ois.close();
		} 
		catch (Exception e)
		{
			return null;
		}

		try
		{
			File f = new File(serDirectory+"/"+Util.byteArrayToHexString(fileNameByteArray)+".ser");
			f.delete();
			System.out.println("File:"+f.getName()+" is deleted successfully!");
		}
		catch(FileNotFoundException e0)
		{
			System.err.println("Can't delete the file..");
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
		return s;
	}


	private void test(Session s)
	{
		serialize(s);
		Session t;
		try {


			t = deserialize(s.getSessionKey());

			System.out.println("After deserialization:");
			System.out.println("SessionKey:"+Util.byteArrayToString(t.getSessionKey()));
			System.out.println("Client Name:"+t.getClientName());
		}
		catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		catch (Exception e1) {
			e1.printStackTrace();
		}
	}


	public static void main(String...args)
	{
		Session s = new Session("I am Prafulla".getBytes(), "Prafulla");
		SessionSerialization ss = new SessionSerialization();
		ss.test(s);
	}
}