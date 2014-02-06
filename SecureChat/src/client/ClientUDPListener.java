package client;

import java.net.DatagramPacket;
import java.net.DatagramSocket;

import com.google.gson.Gson;

import client.Message.*;

public class ClientUDPListener extends Thread{
	
	private Client client;
	private DatagramSocket udp_socket;
	private DatagramPacket packet;
	private boolean alive;
	
	public ClientUDPListener(Client client) {
		this.client=client;
		this.alive=true;
	}
	
	public void run(){
		try{
			byte[] buffer= new byte[4096]; //buffer for message
			Gson gson = new Gson();
			udp_socket = Client.getUdp_socket(); //get client UDP socket
			packet = new DatagramPacket(buffer,buffer.length);
			
			while(alive){
				//rcv packet
				udp_socket.receive(packet);
				String data = new String(packet.getData(), 0, packet.getLength());
				Message msg =(Message) gson.fromJson(data,Message.class);
				
				//if messge is chat message invoke chat handler to print message
				if(msg.getType().equalsIgnoreCase("chatmessage")){
					new ChatHandler(this.client,msg,packet.getAddress(),packet.getPort()).start();
				}
				//if message type is chat then handshake with other user to establish session key
				else if(msg.getType().equalsIgnoreCase("chat")){
					new ClientTcpListner(packet.getPort(),packet.getAddress(),this.client).start();
				}
				//if user sends a logout message, forget session key of user
				else if(msg.getType().equalsIgnoreCase("logout")){
					String usr = Client.getUser_ip().get(packet.getAddress().toString()+String.valueOf(packet.getPort()));
					if(usr!=null){
						Client.getUser_ip().remove(packet.getAddress().toString()+String.valueOf(packet.getPort()));
						Client.getRegistered_users().remove(usr);
					}
				}				
			}
		}catch(Exception e){
			if(alive)
				System.out.println("problem with UDP listener");
		}
	}
	
	public void setAliveFalse(){
		this.alive=false;
	}

}
