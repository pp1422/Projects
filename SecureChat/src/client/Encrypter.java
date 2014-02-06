package client;

import java.io.Serializable;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SealedObject;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Encrypter {
  public byte[] encrypt(byte[] message,byte[] key){
    //message is string to be encrypted
    byte[] encrypted=null;
    try{
      key = Arrays.copyOf(key, 16); //use first 128 bits for encryption
      SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
      Cipher cipher = Cipher.getInstance("AES");
      cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
      encrypted = cipher.doFinal(message); //encrypt the message
     
    }
    catch(Exception e){
      System.out.println("Error occured while encrypting the message");
    }
    return encrypted;
  }
  
  public SealedObject encrypt(Serializable obj,byte[] key){
	  SealedObject encrypted=null;
	    try{
	        key = Arrays.copyOf(key, 16); //use first 128 bits for encryption
	        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
	        Cipher cipher = Cipher.getInstance("AES");
	        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
	        encrypted = new SealedObject(obj,cipher); //encrypt the message
	       
	      }
	      catch(Exception e){
	        System.out.println("Error occured while encrypting the message");
	      }
	      return encrypted;
  }  

	public byte[] encrypt(byte[] plainText, byte[] key_aes,byte[] iv) {
		Cipher cipher;
		byte[] encrypted = null;
		
		try {
			key_aes = Arrays.copyOf(key_aes, 16); //use first 128 bits for encryption
			// Generating key spec for hashed shared key
			IvParameterSpec iv_spec = new IvParameterSpec(iv);
			SecretKeySpec key_spec = new SecretKeySpec(key_aes, "AES");
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key_spec, iv_spec);
			encrypted = cipher.doFinal(plainText);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return encrypted;
	 }
  
}
