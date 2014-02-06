package client;

import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;

import javax.crypto.spec.DHParameterSpec;

@SuppressWarnings("serial")
public class GenerateDHParam  implements Serializable{
	public BigInteger getP() {
		return p;
	}

	public BigInteger getG() {
		return g;
	}

	private BigInteger p;
	private BigInteger g;
	
	public static void main(String arg[]){
		GenerateDHParam dh = new GenerateDHParam();
		dh.genDH();
		dh.writeObject("dh.param");
	}
	
	public void genDH(){
		AlgorithmParameterGenerator paramGen;
		DHParameterSpec dhSpec=null;
		try {
		paramGen = AlgorithmParameterGenerator.getInstance("DH");
		paramGen.init(512); // number of bits
		AlgorithmParameters params = paramGen.generateParameters();
		dhSpec = (DHParameterSpec)params.getParameterSpec(DHParameterSpec.class);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		p = dhSpec.getP();
	    g = dhSpec.getG();
	}

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
}
