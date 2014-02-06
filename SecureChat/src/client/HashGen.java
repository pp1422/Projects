package client;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashGen {
	public byte[] hash(byte[] toHash) {
		MessageDigest sha;
		try {
			sha = MessageDigest.getInstance("SHA-256");
			toHash = sha.digest(toHash);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return toHash;
	}
}
