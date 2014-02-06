package client;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class DigitalSign {

  public byte[] sign(byte[] buffer, PrivateKey privateKey) {
    byte[] signature = new byte[buffer.length];

    try {
      Signature dsa = Signature.getInstance("SHA1withRSA"); //use RSA with SHA1 to create hash of cipher and symmetric key
      dsa.initSign(privateKey);
      dsa.update(buffer, 0, buffer.length);
      //sign the cipher using source private key
      signature = dsa.sign();
    } catch (Exception e) {
      System.out.println("error occured while signing");
    }
    return signature;
  }

  public boolean verify(byte[] signature, byte[] data, PublicKey publicKey) {
    boolean verified = false;
    try {
      Signature sig = Signature.getInstance("SHA1withRSA");
      sig.initVerify(publicKey);
      sig.update(data, 0, data.length);
      /* Update and verify the data */

      verified = sig.verify(signature);
    } catch (Exception e) {
      System.out.println("error occured while verifying sign");
    }
    return verified;
  }
}
