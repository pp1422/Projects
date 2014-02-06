package client;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;

import client.GenerateDHParam;


@SuppressWarnings("serial")
public class UserNamePassword implements Serializable {

	private HashMap<String, BigInteger> userinfo;
	private BigInteger g;
	private BigInteger p;

	public UserNamePassword() {
		userinfo = new HashMap<String,BigInteger>();
	}
	
	public HashMap<String, BigInteger> getUserinfo() {
		return userinfo;
	}
	
	public static void main(String[] args) {
		UserNamePassword userNamePswd=new UserNamePassword();
		String[] userName = {"mit","pratik","strong","weak"};
		String[] pswd = {"@$4321!!", "RY!@$567", "R4532!$%", "HelloWorld123" };
		userNamePswd.initial(userName,pswd);
		userNamePswd.writeObject("username.p");
	}
	
	private void initial(String[] userName, String[] pswd) {
		GenerateDHParam dh = (GenerateDHParam)readObject("dh.param");
		this.g = dh.getG();
		this.p = dh.getP();
		
		for (int i = 0; i < userName.length; i++) {
			BigInteger pswd_hash = new BigInteger(hash(pswd[i].getBytes()));
			BigInteger g_pswd_hash = this.g.modPow(pswd_hash, this.p);
			userinfo.put(userName[i], g_pswd_hash);
		}
	}
	
	// *************** generic functions ****************//
	public void writeObject(String filename) {
	    //writing object into output file
	    ObjectOutputStream obj;
	    try {
	      obj = new ObjectOutputStream(new FileOutputStream(filename));
	      obj.writeObject(this);
	      obj.close();
	    } catch (Exception e) {
	      // TODO Auto-generated catch block
	      System.out.println("error occured while writing object into output file");
	    }
	  }
	
		
	public Object readObject(String filename) {
		ObjectInputStream inputStream = null;
		Object obj = null;

		try {
			inputStream = new ObjectInputStream(new FileInputStream(filename));
			obj = inputStream.readObject();
			inputStream.close();
		} catch (Exception e) {
			System.out
					.println("error occured while reading object from object file");
		}
		return obj;
	}
	
	public static byte[] hash(byte[] toHash) {
		MessageDigest sha;
		try {
			sha = MessageDigest.getInstance("SHA-256");
			toHash = sha.digest(toHash);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return toHash;
	}
}
