package client;

import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.SealedObject;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Decrypter {

	public byte[] decrpyt(byte message[], byte[] key){
		// message contains ciphertext to be decoded
		byte[] original = null;
		SecretKeySpec secretKeySpec;
		try {
			key = Arrays.copyOf(key, 16);
			secretKeySpec = new SecretKeySpec(key, "AES");
			Cipher cipher = Cipher.getInstance("AES");
			// initialize decryption mode and secret key
			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
			// decrypt the ciphertext
			original = cipher.doFinal(message);
		}catch (Exception e) {
			return null;
			/*System.out.println("error occured during decrypting the ciphertext");
			e.printStackTrace();*/
		}
		return original;
	}
	
	public Object decrpyt(SealedObject obj, byte[] key) {
		// message contains ciphertext to be decoded
		Object original = null;
		SecretKeySpec secretKeySpec;
		try {
			key = Arrays.copyOf(key, 16);
			secretKeySpec = new SecretKeySpec(key, "AES");
			Cipher cipher = Cipher.getInstance("AES");
			// initialize decryption mode and secret key
			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
			// decrypt the ciphertext
			original = obj.getObject(cipher);
		} catch (Exception e) {
			System.out.println("error occured during decrypting the ciphertext");
			e.printStackTrace();
		}
		return original;
	}
	
	public byte[] decrpyt(byte[] cipherText, byte[] key_aes,byte[] iv) {
		byte[] decryted = null;
		try {
			key_aes = Arrays.copyOf(key_aes, 16); //use first 128 bits for decryption
			// Generating key spec for hashed shared key
			IvParameterSpec iv_spec = new IvParameterSpec(iv);
			SecretKeySpec key_spec = new SecretKeySpec(key_aes, "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, key_spec, iv_spec);
			decryted = cipher.doFinal(cipherText);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return decryted;
	}
}
