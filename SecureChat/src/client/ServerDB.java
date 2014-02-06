package client;

import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.HashMap;

@SuppressWarnings("serial")
public class ServerDB implements Serializable {

	HashMap<String, BigInteger> userinfo;

	public ServerDB() {
		userinfo = ((UserNamePassword)readObject("username.p"))
				.getUserinfo();
	}

	public BigInteger findPswd(String userName) {
		return userinfo.get(userName.toLowerCase());
	}

	public static void main(String[] args) {
		ServerDB obj=new ServerDB();
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
}