package client;

import java.io.BufferedReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Map;

import javax.crypto.SealedObject;

import com.google.gson.Gson;

import client.Message.*;

public class ListCommandHandler extends Thread{
	
	private Socket connection;
	private BufferedReader in;
	private PrintWriter out;
	private BigInteger g,p;
	private Message msg;
	private Server server;
	
	public ListCommandHandler(Socket connection, BufferedReader in,
			PrintWriter out, Server server, Message msg) {
		this.connection=connection;
		this.in=in;
		this.out=out;
	    this.msg=msg;
	    this.server=server;
	}
	
	public void run(){
		try {
			// generate Nonce
			Gson gson = new Gson();
			msg=new Message();
			RSA rsa = new RSA();
			Encrypter enc = new Encrypter();
			Decrypter dec = new Decrypter();
			
			Message.LstMessage1 msg1 = msg.new LstMessage1();
			BigInteger N1=new NonceGen().genNonce();
			msg1.setN1(N1);
			msg.setLstmsg1(msg1);

			out.println(gson.toJson(msg, Message.class));

			msg = (Message)gson.fromJson(in.readLine(),Message.class);
			LstMessage2 msg2 = msg.getLstmsg2();
			
			String username=new String(
				rsa.decrypt(msg2.getUsername(),server.getServerPrivateKey()));
			
			User user=Server.getRegistered_users().get(username);
			
			if(user==null){
				System.out.println("user not matched");
				return;
			}
			
			BigInteger Ksa = user.getSharedKey();
			HashGen hashGen = new HashGen();
			byte[] hashSK = hashGen.hash(Ksa.toByteArray());
			
			byte[] N1rsadec =rsa.decrypt(msg2.getEnc_N1().toByteArray(),server.getServerPrivateKey());
			BigInteger clientN1 = new BigInteger(dec.decrpyt(N1rsadec,hashSK));
			
			if(!N1.equals(clientN1)){
				//error
				System.out.println("replayed message");
				return;
			}
			
			BigInteger N2 = new BigInteger(rsa.decrypt(msg2.getN2().toByteArray(),server.getServerPrivateKey()));
			
			LstMessage3 msg3 = msg.new LstMessage3();
			msg3.setN2(N2);
			msg3.setUsers(new ArrayList<String>(Server.getRegistered_users().keySet()));
			msg.setLstmsg3(msg3);
			
			out.println(gson.toJson(new Encrypter().encrypt(msg,hashSK),SealedObject.class));
	
			connection.close();
		} catch (Exception e) {
			System.out.println("cannot serve list command from server");
		}
	}

}
