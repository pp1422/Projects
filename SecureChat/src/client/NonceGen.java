package client;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class NonceGen {
	public BigInteger genNonce(){
		byte[] seed = SecureRandom.getSeed(16);
		BigInteger seedBI=new BigInteger(seed);
		if(seedBI.signum() == -1)
			seedBI = seedBI.multiply(new BigInteger("-1"));
			
		SecureRandom sr=null;
		try {
			sr = SecureRandom.getInstance("SHA1PRNG");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		sr.setSeed(seed);
		byte[] nonce = new byte[16];
		sr.nextBytes(nonce);
		BigInteger nonceBI=new BigInteger(nonce);
		if(nonceBI.signum() == -1)
			nonceBI = nonceBI.multiply(new BigInteger("-1"));
		
		return nonceBI;
	}
}
