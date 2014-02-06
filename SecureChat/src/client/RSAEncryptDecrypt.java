package client;

import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;


public class RSAEncryptDecrypt {
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
    }
    return cipherText;
  }
}
