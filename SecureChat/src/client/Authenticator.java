package client;

import java.io.BufferedReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Map;

import javax.crypto.BadPaddingException;

import client.Message.Message1;
import client.Message.Message3;
import client.Message.Message5;
import client.Message.Message6;

import com.google.gson.Gson;

public class Authenticator extends Thread{
	
	private Socket connection;
	private BufferedReader in;
	private PrintWriter out;
	private BigInteger g,p;
	private Message msg;
	private Map<String, User> registered_users;
	private Map<String, String> msgstate;
	private Server server;
	private int b;
	

	public Authenticator(Socket connection, BufferedReader in,
			PrintWriter out, Server server, Message msg) {
		this.connection=connection;
		this.in=in;
		this.out=out;
	    this.msg=msg;
	    this.server=server;
	}

	public void run(){
		try{
			SecureRandom ranGen1 = new SecureRandom();
			RSA rsa = new RSA();
			Gson gson = new Gson();
			HashGen hgen = new HashGen();
			
			Message1 msg1 = msg.getMsg1();
			
			//set DH parameter of server
			this.g=server.getG();
			this.p=server.getP();
		
			//generate puzzle
		
			BigInteger x = new BigInteger(16,ranGen1);
			
			if(x.intValue()<-1){
				x=x.abs();
			}
			
			//send puzzle to user
			Message msgX = new Message();
			byte[] puzzle=hgen.hash(x.toByteArray());
			Message.Message2 msg2 = msgX.new Message2();
			msg2.setPuzzle(puzzle);
			msgX.setMsg2(msg2);
			
		    out.println(gson.toJson(msgX,Message.class));
		    // puzzle generated
		    
		  //verify user response
		    msgX= gson.fromJson(in.readLine(),Message.class);
		    Message3 msg3 = msgX.getMsg3();
		    
		    if(!msg3.getPuzzle_response().equals(x)){
		    	System.out.println("puzzle does not match");
		    	msg.setType("Invalid_puzzle");
		    	out.println(gson.toJson(msg,Message.class));
		    	return;
		    }
		
		    byte[] usr = msg1.getUsername();
		    BigInteger A = msg1.getA();
		
		    String username = new String(rsa.decrypt(usr,server.getServerPrivateKey()));
		    
		    //check if user is already logged in
		    if(Server.getRegistered_users().get(username)!=null){
		    	msg.setType("already_logged_in");
		    	out.println(gson.toJson(msg,Message.class));
		    	return;
		    }
		
		    //read g^w mod p from database file for given user
		    ServerDB sdb = new ServerDB();
		    BigInteger W = sdb.findPswd(username); // read W from file belonging to given username
		    
		    if(W==null){
		    	msg.setType("Invalid_userName");
		    	out.println(gson.toJson(msg,Message.class));
		    	return;
		    }
	
		    BigInteger B = calculateB(W);		

		    // generating u and c1
		    int u = ranGen1.nextInt((int) Math.pow(2, 8));
		    BigInteger c1 = new BigInteger(128, ranGen1);

		    Message msg = new Message();
		    Message.Message4 msg4 = msg.new Message4();
		    msg4.setB(B);
			msg4.setU(u);
			msg4.setC1(c1);
			msg.setMsg4(msg4);

			String json = gson.toJson(msg);
			out.println(json);
		
			//compute shared key between client and server
			BigInteger key = computeSharedKey(A, u, W);

			String dataMsg5 = in.readLine();
			msg = (Message) gson.fromJson(dataMsg5, Message.class);
			Message5 msg5 = msg.getMsg5();

			//generate hash of shared key
			HashGen hashGen = new HashGen();
			byte[] hashSK = hashGen.hash(key.toByteArray());

			Decrypter decrypt = new Decrypter();
			BigInteger clientC1 = null;

			//decrypt c1 to authenticate client
			byte[] clientC1_byte = decrypt.decrpyt(msg5.getEnc_c1()
					.toByteArray(), hashSK);
			
			//if c1 cannot be decrypted then user password is invalid
			if (clientC1_byte == null) {
				msg.setType("Invalid_Password");
				out.println(gson.toJson(msg, Message.class));
				return;
			}
		
			clientC1 = new BigInteger(clientC1_byte);
		
			Encrypter encrypt = new Encrypter();
			BigInteger c2 = new BigInteger(encrypt.encrypt(msg5.getC2()
					.toByteArray(), hashSK));
			
			//send enrypted C2 to authenticate server
			Message6 msg6 = msg.new Message6();
			msg6.setEnc_c2(c2);
			msg.setMsg6(msg6);
			out.println(gson.toJson(msg, Message.class));

			//register user 
			User user = new User(username, connection.getInetAddress(),
					connection.getPort(), W, key);
			Server.getRegistered_users().put(username, user);

			//close connection
			connection.close();
		}
		catch(Exception e){
			System.out.println("error on server while authenticating");
		}
	}

	//calculate (g^b + W)
	private BigInteger calculateB(BigInteger W){
		
		SecureRandom ranGen1 = new SecureRandom();
		this.b = ranGen1.nextInt((int) Math.pow(2, 8));
		
		//compute g^b
		BigInteger B1 = this.g.pow(b);

		return B1.add(W);
	}
	
	//compute shared key for user and server
	private BigInteger computeSharedKey(BigInteger A, int u, BigInteger W) {

		int ub = u * this.b;
		BigInteger uWb = W.modPow(BigInteger.valueOf(ub),this.p);   

		// instead of g^ubW mod p
		BigInteger AB = A.pow(b).mod(this.p);

		// key (g^(b*(a+uW)) mod p)
		return (AB.multiply(uWb)).mod(this.p);
	}
}
