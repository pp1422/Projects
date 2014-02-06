package client;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class Hmac {

	public byte[] getHmac(byte[] data,byte[] key){
		byte[] hmac=null;
		try{
			SecretKeySpec key_spec=new SecretKeySpec(key,"HmacSHA1");
			Mac mac=Mac.getInstance("HmacSHA1");
			mac.init(key_spec);
			
			hmac = mac.doFinal(data);
		}
		catch(Exception e){
			e.printStackTrace();
		}
		return hmac;
	}
}
