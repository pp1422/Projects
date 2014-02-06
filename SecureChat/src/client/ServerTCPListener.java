package client;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import client.Message.ChatMessage;
import com.google.gson.Gson;

public class ServerTCPListener extends Thread{
	
	private ServerSocket serverSocket; //server tcp socket
	private Server server; //server object 
	private Socket connection; //connection socket between client and server
	private boolean alive;
	
	public ServerTCPListener(ServerSocket tcpServerSocket, Server server) {
		this.serverSocket=tcpServerSocket;
		this.server=server;
		alive=true;
	}

	public void run(){
		// This tread listens to incoming TCP connections from users who
		// want to authenticate or get the list of online users or logout
		// from the chat system
		
		Gson gson = new Gson();
		String data;
		
		while(alive){
			try{
				//wait for client connections
				connection=serverSocket.accept();
				BufferedReader in = new BufferedReader(
		                new InputStreamReader(
		                    connection.getInputStream()));
				
				PrintWriter out = new PrintWriter(connection.getOutputStream(), true);
				
				//read message
				data=in.readLine();
				
				Message msg=null;
				
				//check for list request
				if(data.equals("list")){
					//start new thread to server list request
					new ListCommandHandler(connection,in,out,server,msg).start();
				}
				else {
					msg = (Message) gson.fromJson(data, Message.class);
					String msgtype=msg.getType();
					
					// Login
					if (msgtype.equalsIgnoreCase("login.msg1")) {
						new Authenticator(connection, in, out, server, msg).start();
					}
					else if(msgtype.equalsIgnoreCase("chatrequest")){
						new ChatServer(connection, in, out,server,msg).start();
					}
					else if(msgtype.equalsIgnoreCase("logout")){
						ChatMessage chatmsg = msg.getChatmsg();
						byte[] username = new RSA().decrypt(chatmsg.getMessage(),server.getServerPrivateKey());
						Server.getRegistered_users().remove(new String(username));
					}
				}
			}catch(Exception e){
				if(alive)
					System.out.println("problem with server tcp listener");
			}			
		}
	}

	public void setAliveFalse(){
		alive=false;
		
		try{
			this.serverSocket.close();
		}
		catch(Exception e){
		 //probably server socket close	
			System.out.println("Probably server socket closed");
		}
	}
}
