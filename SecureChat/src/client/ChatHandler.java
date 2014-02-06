package client;

import java.net.InetAddress;
import java.util.Arrays;

import client.Message.ChatMessage;

public class ChatHandler extends Thread{
	
	private Message msg;
	private InetAddress source_ip;
	private int source_port;
	
	public ChatHandler(Client client, Message msg, InetAddress inetAddress, int port) {
		this.msg=msg;
		this.source_ip=inetAddress;
		this.source_port=port;
	}
	
	public void run(){
		byte[] iv;
		ChatMessage chat = msg.getChatmsg();	
		//retrieve username from received packet
		String username=Client.getUser_ip().get(source_ip.toString()+String.valueOf(source_port));
		
		//get user details from stored user details
		User user = (User)Client.getRegistered_users().get(username);
		
		//generate hash of shared key
		HashGen hasher = new HashGen();
		byte[] key = hasher.hash(user.getSharedKey().toByteArray());
		
		//verify hmac for integrity of message
		byte[] hmac_verify=new Hmac().getHmac(chat.getMessage(),key);
		
		//if HMAC verifies then print the message
		if(Arrays.equals(hmac_verify,chat.getHmac())){
			System.out.println("Message Received from User: "+user.getUsername());
			iv=user.getW().toByteArray();
			String message = new String(new Decrypter().decrpyt(chat.getMessage(),key,iv));
			System.out.println("Message: "+message);
		}else{
			System.out.println("corrupted message");
		}
	}
}
