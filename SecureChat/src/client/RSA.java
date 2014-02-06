package client;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;
import javax.crypto.SealedObject;


public class RSA {
  public byte[] encrypt(byte[] text, PublicKey key) {
    byte[] cipherText = null;
    try {
      // get an RSA cipher object and print the provider
      final Cipher cipher = Cipher.getInstance("RSA");
      // encrypt the plain text using the public key
      cipher.init(Cipher.ENCRYPT_MODE, key);
      cipherText = cipher.doFinal(text);
    } catch (Exception e) {
      System.out.println("error occured during RSA encyption");
      e.printStackTrace();
    }
    return cipherText;
  }
  
  public SealedObject encrypt(Serializable obj, PublicKey key) {
	    SealedObject cipherText = null;
	    try {
	      // get an RSA cipher object and print the provider
	      final Cipher cipher = Cipher.getInstance("RSA");
	      // encrypt the plain text using the public key
	      cipher.init(Cipher.ENCRYPT_MODE, key);
	      cipherText = new SealedObject(obj,cipher);
	    } catch (Exception e) {
	      System.out.println("error occured during RSA encyption");
	      e.printStackTrace();
	    }
	    return cipherText;
	  }
  
  public byte[] decrypt(byte[] text, PrivateKey key) {
    byte[] cipherText=null;
    try {
      // get an RSA cipher object and print the provider
      final Cipher cipher = Cipher.getInstance("RSA");
      // encrypt the plain text using the public key
      cipher.init(Cipher.DECRYPT_MODE, key);
      cipherText = cipher.doFinal(text);
    } catch (Exception e) {
      System.out.println("error occured while decrypting using RSA");
      e.printStackTrace();
    }
    return cipherText;
  }
  
  public Object decrypt(SealedObject obj, PrivateKey key) {
	    Object cipherText=null;
	    try {
	      // get an RSA cipher object and print the provider
	      final Cipher cipher = Cipher.getInstance("RSA");
	      // encrypt the plain text using the public key
	      cipher.init(Cipher.DECRYPT_MODE, key);
	      cipherText = obj.getObject(cipher);
	    } catch (Exception e) {
	      System.out.println("error occured while decrypting using RSA");
	      e.printStackTrace();
	    }
	    return cipherText;
	  }
}

