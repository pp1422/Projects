package client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.security.SecureRandom;
import client.Message.Chat3;
import client.Message.MessageTicket;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import com.google.gson.Gson;

public class ClientTcpListner extends Thread {
	
	private Client client;
	private InetAddress sender_ipaddress;
	private int sender_port;
	
	public ClientTcpListner(int port, InetAddress address, Client client) {
		// TODO Auto-generated constructor stub
		this.client=client;
		this.sender_ipaddress=address;
		this.sender_port=port;
	}

	@Override
	public void run() {

		Gson gson = new Gson();
		String data;
		BigInteger g=client.getG();
		BigInteger p=client.getP();

			try {
				//establish client tcp socket to given sender
				Socket client_tcp_socket=new Socket(this.sender_ipaddress,this.sender_port);
				
				BufferedReader in = new BufferedReader(new InputStreamReader(
						client_tcp_socket.getInputStream()));
				PrintWriter out = new PrintWriter(client_tcp_socket.getOutputStream(),
						true);

				data = in.readLine();

				// Receive msg
				Message msg = (Message) gson.fromJson(data, Message.class);
				Message.Chat1 chat1 = msg.new Chat1();
				chat1 = msg.getChat1();
                 
				// Get the ticket encrypted by shared key between client and
				// server
				SealedObject ticket = chat1.getEnc_ticket();
				// Get the ticket
				MessageTicket msgticket = (MessageTicket) (new Decrypter())
						.decrpyt(ticket, client.getHashSharedKey());
				// Check if the receiver matches with the userName of this
				// object
				if (msgticket.getIntendedReceiver().equals(client.getUserid())) {
					// extract session key from ticket
					SecretKey Kab = msgticket.getSessionKey();
					// Get encrypted DH Contri of sender
					BigInteger DH_Sender = new BigInteger(
							(new Decrypter()).decrpyt(chat1.getEnc_new_key(),
									Kab.getEncoded()));

					// Generating b
					SecureRandom ranGen = new SecureRandom();
					int b = ranGen.nextInt((int) Math.pow(2, 8));
					
					// Generating g^b mod p
					BigInteger DH_Receiver = g.pow(b).mod(p);
					
					// Encrypted Diffie Hellman of Receiver using Session Key
					byte[] enc_DH_Receiver = (new Encrypter()).encrypt(
							DH_Receiver.toByteArray(),
							Kab.getEncoded());
					
					// Generate the chat_sharedSecret g^ab mod p
					BigInteger chat_sharedSecret = DH_Sender.pow(b).mod(p);
						
					HashGen hshgen = new HashGen();
					byte[] hash_chat_sharedSecret = hshgen
							.hash(chat_sharedSecret.toByteArray());

					// Extracting the challenge
					BigInteger c1 = chat1.getC1();
					// Encrypting the challenge
					
					//retrieve encrypted iv from message
					 byte[] enc_iv=chat1.getIv();
					 
					 //decrypt iv
	                 byte[] iv=new Decrypter().decrpyt(enc_iv, Kab.getEncoded());
					
					byte[] enc_c1 = (new Encrypter().encrypt(c1.toByteArray(),
							hash_chat_sharedSecret,iv));
					
					// Generating c2
					BigInteger c2=new BigInteger(128, ranGen);
					
					
					// Preparing the message to be sent.
					Message.Chat2 chat2 = msg.new Chat2();
					chat2.setEnc_ack(enc_DH_Receiver);
					chat2.setEnc_c1(enc_c1);
					chat2.setC2(c2);
					
					// Sending the message
					msg.setChat2(chat2);
					out.println(gson.toJson(msg,Message.class));
					
					// Receiving enc_c2 from sender
					String chat3 = in.readLine();
					Message o_msg_chat3 = (Message)gson.fromJson(chat3, Message.class);
					Chat3 o_chat3 = o_msg_chat3.getChat3();
					
					// Decrypting enc_c2 using hash_chat_sharedSecret
					BigInteger verify_c2 = new BigInteger((new Decrypter()).decrpyt(o_chat3.getEnc_c2(), hash_chat_sharedSecret,iv));
					
					if(verify_c2.equals(c2)){
						// Creating user object to store details
						  User user=new User(
								  msgticket.getSender(),
								  msgticket.getSenderIp(), 
								  msgticket.getSenderPort(), 
								  new BigInteger(iv), 
								  chat_sharedSecret);
						  // Add to hash map
						  Client.getRegistered_users().put(msgticket.getSender(),user);
						  Client.getUser_ip().put(this.sender_ipaddress.toString()+String.valueOf(this.sender_port),
								  msgticket.getSender());
					
						  //send readdy for chat
						  out.println(new String("ACK"));
						  
						//close socket
						  client_tcp_socket.close();  

					}
					else{
						System.out.println("Chat cancelled");
						//close socket
						  client_tcp_socket.close();
					}
				} else {
					System.out
							.println("ticket was not intended for me but it was intended for "
									+ msgticket.getIntendedReceiver());
				}

			} catch (Exception e) {
				e.printStackTrace();
			}

		}

	//}

}
