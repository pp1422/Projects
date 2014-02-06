package client;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;

import com.google.gson.Gson;

public class ChatServer extends Thread {
	private Socket connection;
	private BufferedReader in;
	private PrintWriter out;
	private Message msg;
	private Server server;

	public ChatServer(Socket connection, BufferedReader in, PrintWriter out,
			Server server, Message msg) {
		this.connection = connection;
		this.in = in;
		this.out = out;
		this.server = server;
		this.msg = msg;
	}

	public void run() {

		
		Message.MessageRequestChat req_new = msg.new MessageRequestChat();
		req_new = msg.getRqChat();
		//retrieve sender user name
		String sender_userName = new String(new RSA().decrypt(req_new.getEnc_userName(), server.getServerPrivateKey()));
		
		User sender,receiver;
		
		if((sender=Server.getRegistered_users().get(sender_userName)) != null){
			
			//get sender shared key
			byte[] hashSK_sender= new HashGen().hash(sender.getSharedKey().toByteArray());
			 
			//get receiver
			byte[] receiver_userName = (new Decrypter()).decrpyt(req_new.getEnc_receiver_name(), hashSK_sender);
			
			
			if((receiver = Server.getRegistered_users().get(new String (receiver_userName))) != null){
				
				byte[] receiver_hashSK = new HashGen().hash(receiver.getSharedKey().toByteArray());
				
				//generate Kab and forget it
				SecretKey sessionKey=this.generateAES128Key();
				
				//generate ticket for B
				SealedObject so_ticket = generateTicket(receiver_hashSK,sender,sessionKey,receiver.getUsername());
				
				// encrypted session key packet for A
				SealedObject so_sessionKey = generateSessionKey(receiver,hashSK_sender,sessionKey);
				
				//Signing the entire message
				Message.SessionKeyPlusTicket skpt = msg.new SessionKeyPlusTicket();
				skpt.setEncryptedSessionKey(so_sessionKey);
				skpt.setEncrypytedticket(so_ticket);
				msg.setSkpt(skpt);
				byte[] test_ba = objToByteArray(msg);
				byte[] signature = (new DigitalSign()).sign(test_ba, server.getServerPrivateKey());
				Message.SessionKeyTicketSign skts=msg.new SessionKeyTicketSign();
				skts.setSignature(signature);
				skts.setByteArrayOfObject(test_ba);
				msg.setSkts(skts);
				out.println((new Gson()).toJson(msg,Message.class));
				closeConnection();
			}
			else{
				// Receiver is either not online or username is incorrect
				out.println("Invalid");
				//connection should be closed
				closeConnection();
			}					
		}
		else{
			System.out.println("Sender Name incorrect");
			//connection closed
			out.println("Invalid");
			closeConnection();
		}
	}
	
	//close connection
	private void closeConnection(){
		try{
			this.connection.close();
		}catch(Exception e){
			e.printStackTrace();
		}
	}

	//convert object to byte array
	private byte[] objToByteArray(Message msg){
		byte[] ba=null;
		ByteArrayOutputStream byte_Arr_os=new ByteArrayOutputStream();
		ObjectOutputStream obj_out_strm;
		try {
			obj_out_strm = new ObjectOutputStream(byte_Arr_os);
			obj_out_strm.writeObject(msg);
			obj_out_strm.flush();
			obj_out_strm.close();
			byte_Arr_os.close();
			ba=byte_Arr_os.toByteArray();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		return ba;
	}
	private SealedObject generateSessionKey(User receiver, byte[] hashSK_sender, SecretKey key) {
		// Ksa {Kab, IPb,Portb}
		Message.MessageSessionKey sessionKey=msg.new MessageSessionKey();
		sessionKey.setReceiver_ip(receiver.getIpaddress());
		sessionKey.setReceiver_port(receiver.getPort());
		sessionKey.setSessionKeyWithReceiver(key);
		
		SealedObject so=(new Encrypter()).encrypt(sessionKey, hashSK_sender);
		return so;
	}

	private SealedObject generateTicket(byte[] receiver_hashSK,
			User sender, SecretKey sessionKey, String receiver_UserName) {
		//TICKET = Ksb {Kab, IPa,Porta,”A”}
		Message.MessageTicket ticket=msg.new MessageTicket();
		ticket.setSender(sender.getUsername());
		ticket.setIntendedReceiver(receiver_UserName);
		ticket.setSenderIp(sender.getIpaddress());
		ticket.setSenderPort(sender.getPort());
		ticket.setSessionKey(sessionKey);
		
		SealedObject so = (new Encrypter()).encrypt(ticket, receiver_hashSK);
		return so;
		
	}
	public SecretKey generateAES128Key(){
		KeyGenerator keyGen;
		SecretKey secretKey = null;
		try {
			keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(128);
			secretKey = keyGen.generateKey();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return secretKey;
		
	}
}
