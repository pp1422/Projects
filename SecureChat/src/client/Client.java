package client;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.lang.reflect.Type;
import java.math.BigInteger;
import java.net.BindException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.SealedObject;
import javax.crypto.SecretKey;

import client.Message.Chat2;
import client.Message.ChatMessage;
import client.Message.LstMessage2;
import client.Message.LstMessage3;
import client.Message.Message3;
import client.Message.Message4;
import client.Message.Message5;
import client.Message.Message6;
import client.Message.MessageSessionKey;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

public class Client {

	private String userid;
	private String password;
	private int a; // clients' random number for server authentication
	private BigInteger g; // pre determined g forDH
	private BigInteger p; // pre determined p for DH
	private BigInteger A; // g^a mod p
	private int server_port; // server UDP port
	private int server_tcp_port; // server TCP port
	private PublicKey serverkey; //public key of server
	private InetAddress serverIP; //server ip address
	private Socket client_tcp_socket; //client tcp socket 
	private static int port;  //client tcp udp port
	private BigInteger sharedKey; //shared key of client with server
	private byte[] hashSharedKey; // hash of shared key with server
	private ServerSocket clntAsServersocket; //client as server socket 
	private static Map<String, User> registered_users; //list of all users for which client has key
	private static Map<String, String> user_ip; //mapping of ip-address+port number to User
	private static DatagramSocket udp_socket; // client udp socket
	private static boolean logged_in; //true iff user is logged_in
	private static ClientUDPListener listener; //client udp listener
	
	public Client() {
		userid = null;
		password = null;
		registered_users = Collections.synchronizedMap(new HashMap<String, User>());
		user_ip=Collections.synchronizedMap(new HashMap<String, String>());
		logged_in=false;
	}

	public static void main(String[] args) {
		Client client = new Client();
		
		try {
			// ask user for login id and password
			client.getUserIdPassword();
			
			// Start authentication from server
			System.out.println("wait for authentication");

			// get server details from config file
			client.getServerDetails();

			// get DH parameters from config file and calculate A (g^a mod p) of client
			client.getDHKey();

			// initialize tcp socket of client to connect to server
			client.initializeTCPSocket();

			//authenticate client from server
			client.authenticate();
			
			//log-in user
			logged_in=true;
			
			//initialize tcp socket of client to act as server for other clients
			client.initClientAsServerTCPSocket();
			
			//read commands continously from console
			client.readfromConsole();
			
		} catch (Exception e) {
			e.printStackTrace();  //removee
			System.out.println("error in client application");
		}finally{
			if (logged_in) {
				client.logoutUser();
				logged_in=false;
			}
			listener.setAliveFalse();
			client.closeUDPSocket();
		}
	}
	
	//close UDP socket
	private void closeUDPSocket(){
		try{
			Client.udp_socket.close();
		}catch(Exception e){
			System.out.println("cannot close client");
		}
	}

	//initalize tcp connection of client with server
	private void initializeTCPSocket() {
		try {
			this.client_tcp_socket = new Socket(this.serverIP,
					this.server_tcp_port);
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	//initialize client as server for other users
	private void initClientAsServerTCPSocket() {

		try {
			this.clntAsServersocket = new ServerSocket(Client.port);
		}	
		catch(BindException be){
			initClientAsServerTCPSocket();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	//get user id password from console
	private void getUserIdPassword() {
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));

		try {
			System.out.println("Please enter your Username");
			this.userid = br.readLine();
			this.userid=this.userid.toLowerCase();
			System.out.println("Please enter your Password");
			this.password = br.readLine();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public InetAddress getServerIP() {
		return serverIP;
	}

	public void setServerIP(InetAddress serverIP) {
		this.serverIP = serverIP;
	}

	//read server config file to retrieve server details 
	private void getServerDetails() {
		ServerConfig sc = (ServerConfig) readObject("Server.conf");
		this.serverIP = sc.getIpaddress(); 
		this.setServer_port(sc.getPort());
		this.server_tcp_port = sc.getTcp_port();
		this.serverkey = getPublicKey("server-public.key");
	}

	//authenticate client from server
	private void authenticate() {
		
		
		RSA rsa = new RSA();
		//send message to server
		Gson gson = new Gson();
	
		try {
			
			BufferedReader in = this.getIpStream();
			PrintWriter out = this.getOpStream();
			HashGen hshgen = new HashGen();
			
			//1. encrypt username with server public key
			byte[] username = rsa.encrypt(userid.getBytes(), serverkey);
			
			//create Message ({A}server-public key and (g^a mod p))
			Message msg = new Message();
			Message.Message1 msg1 = msg.new Message1();
			msg1.setUsername(username);
			msg1.setA(this.A);
			msg.setMsg1(msg1);
			
			//conver message class oject into Json string
			String json = gson.toJson(msg);	
			
			// GREET The Server
			out.println(json);
			
			
			// recieve puzzle from server
			Message puzmsg = (Message) (gson.fromJson(in.readLine(),
					Message.class));
			byte puzzle[] = puzmsg.getMsg2().getPuzzle();

			byte[] newhash;
			BigInteger b1 = BigInteger.ZERO;

			Message3 msg3 = puzmsg.new Message3();

			//solve puzzle
			while (true) {

				newhash = hshgen.hash(b1.toByteArray());

				if (Arrays.equals(puzzle, newhash)) {
					msg3.setPuzzle_response(b1);
					puzmsg.setMsg3(msg3);
					out.println(gson.toJson(puzmsg, Message.class));
					break;
				} else {
					b1 = b1.add(BigInteger.ONE);
				}
			}

			// Receive DH contribution of server
			String dataMsg4 = in.readLine();

			msg = gson.fromJson(dataMsg4, Message.class);
			
			//check if username enterd by user is invalid
			if(msg.getType().equals("Invalid_userName")){
				System.out.println("Invalid username");
				getUserIdPassword();
				initializeTCPSocket();
				authenticate();
				return;
			}
			//check if user is already logged in
			else if(msg.getType().equalsIgnoreCase("already_logged_in")){
				System.out.println("User already logged in");
				getUserIdPassword();
				initializeTCPSocket();
				authenticate();
				return;
			}
			
			//if username is valid compute shared key and send challange
			// to authenticate server and get itself authenticated
			Message4 msg4 = msg.getMsg4();
			BigInteger B = msg4.getB(); //server DH contibution
			BigInteger c1 = msg4.getC1(); //challenge from server
			int u = msg4.getU(); //received U from server

			// compute shared key (g^(b*(a+uW)) mod p)
			BigInteger sharedKey = this.computeSharedKey(B, u);
			this.sharedKey = sharedKey;

			// hash shared key to be used for encrytion
			byte[] hashSK = hshgen.hash(sharedKey.toByteArray());
			this.hashSharedKey = hashSK;

			Encrypter encrypt = new Encrypter();
			
			//create challenge c2 and also send encrypted c1 to server
			msg = new Message();
			Message5 msg5 = msg.new Message5();
			msg5.setEnc_c1(new BigInteger(encrypt.encrypt(c1.toByteArray(),
					hashSK)));

			//generate random number C2
			SecureRandom ranGen1 = new SecureRandom();
			BigInteger c2 = new BigInteger(128, ranGen1);
			msg5.setC2(c2);
			msg.setMsg5(msg5);

			json = gson.toJson(msg, Message.class);
			out.println(json);
			
			//read encrypted c2 from server
			String str6 = in.readLine();
			msg = gson.fromJson(str6, Message.class);
			
			//if c1 does not match password is incorrect
			if(msg.getType().equals("Invalid_Password")){
				System.out.println("Incorrect Password");
				getUserIdPassword();
				initializeTCPSocket();
				authenticate();
				return;
			}
			
			//receive C2 from server and authenticate server
			Message6 msg6 = msg.getMsg6();
			BigInteger c2Server = msg6.getEnc_c2();

			Decrypter decrypt = new Decrypter();
			BigInteger newC2 = new BigInteger(decrypt.decrpyt(
					c2Server.toByteArray(), hashSK));
			
			//if c2 does not match then server is fake
			if (c2.equals(newC2)) {
				System.out.println(this.userid+" authenticated");
				Client.setPort(client_tcp_socket.getLocalPort());
				this.initializeUDPSocket();
				listener=new ClientUDPListener(this);
				listener.start();
			} else{
				System.out.println("Server is fake");
				System.exit(0);
			}
			this.client_tcp_socket.close();
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	//initialize UDP socket for receiver
	private void initializeUDPSocket() {

		try {
			Client.setUdp_socket(new DatagramSocket(this.getPort()));
		} catch (SocketException e) {
			e.printStackTrace();
		}
	}

	//get input stream from client tcp socket
	public BufferedReader getIpStream() {
		try {
			return new BufferedReader(new InputStreamReader(
					this.client_tcp_socket.getInputStream()));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	//write output stream to tcp socket
	public PrintWriter getOpStream() {
		try {
			return new PrintWriter(this.client_tcp_socket.getOutputStream(),
					true);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	//read continously from console
	public void readfromConsole() {
		Scanner sc = new Scanner(System.in);
		String chat[];

		while (true) {
			// read next line
			String cmd = sc.nextLine();

			// check if input command is list
			if (cmd.equalsIgnoreCase("list")) {
				this.handleListRequest();
			} 
			//check if user wants to log out
			else if (cmd.equalsIgnoreCase("logout")) {
				logoutUser();
				closeSocket();
				break;
			} 
			//else check if user wants to send message
			else {
				chat = cmd.split("\\s+", 3);

				if (chat[0].equalsIgnoreCase("send")) {
					if(chat.length<3){
						System.out.println("receiver and message cannot be null");
					}
					else
						this.handleChatRequest(chat[1], chat[2]);
				}
				else{
					System.out.println("Invalid command");
				}
			}
		}
		sc.close();
	}

	//close server socket of client
	private void closeSocket() {
		// TODO Auto-generated method stub
		try{
			this.clntAsServersocket.close();
		}catch(Exception e){
			e.printStackTrace();
		}
	}

	//log out user
	private void logoutUser() {
		
		ArrayList<String> users = new ArrayList<String>(
				Client.registered_users.keySet());
		User user;
		
		//send logout message to all users with which session was established
		for (String username : users) {
			user = Client.registered_users.get(username);
			sendUDPMessage(user, "logout", false, "logout");
		}

		//send logout message to server
		try {
			this.initializeTCPSocket();
			PrintWriter out = this.getOpStream();
			Message msg = new Message();

			ChatMessage chat = msg.new ChatMessage("logout");
			
			byte[] enc_message;

			enc_message = new RSA().encrypt(this.userid.getBytes(),
					this.serverkey);

			chat.setMessage(enc_message);
			msg.setChatmsg(chat);
			String data = new Gson().toJson(msg, Message.class);
			out.println(data);
			logged_in=false;
			System.out.println("Good Bye");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	//handle chat request
	private void handleChatRequest(String receiver, String message) {
		
		receiver=receiver.toLowerCase();
		
		if(receiver.equalsIgnoreCase(this.userid)){
			System.out.println("source and destination cannot be same");
			return;
		}
			
		User user = Client.registered_users.get(receiver.trim());
		Message msg = new Message();
		Encrypter encrypt = new Encrypter();
		Gson gson = new Gson();

		if (user == null) {
			// establish key since user is new to session

			try {
				initializeTCPSocket();
				BufferedReader in = this.getIpStream();
				PrintWriter out = this.getOpStream();

				
				// create a message {A,"chat","B"}
				if (this.userid.equals(receiver)) {
					System.out.println("Enter a valid user Name. The receiver is same as the sender");
				} else {
					// encrypt username
					byte[] enc_userName = new RSA().encrypt(
							this.userid.getBytes(), serverkey);

					//encrypt receiver name
					byte[] enc_receiver_name = encrypt.encrypt(
							receiver.getBytes(), hashSharedKey);

					// Setting up the message object to be sent
					Message.MessageRequestChat req = msg.new MessageRequestChat();
					req.setEnc_userName(enc_userName);
					req.setEnc_receiver_name(enc_receiver_name);
					msg.setRqChat(req);

					// create the json object
					out.println(gson.toJson(msg, Message.class));

					String msg_from_server = in.readLine();
					
					//If receiver username is not valid then print error
					if (msg_from_server.equalsIgnoreCase("Invalid")) {
						System.out.println(receiver
								+ " is not availble/is not a valid user id");
					}
					// 1. decrypt using server's public key.
					else {

						msg = (Message) gson.fromJson(msg_from_server,
								Message.class);
						Message.SessionKeyTicketSign skts = msg.new SessionKeyTicketSign();
						skts = msg.getSkts();
						byte[] sign = skts.getSignature();
						byte[] object = skts.getByteArrayOfObject();

						// verify the digital signature
						if (!(new DigitalSign().verify(sign, object,
								this.serverkey))) {
							System.out
									.println("Signature doesn't match. Server not legi");
						} else {
							// Deserialize the object
							msg = (Message) byteArrayToObj(object);
							// Getting the inner class
							Message.SessionKeyPlusTicket skpt = msg.getSkpt();
							// Getting ticket and session key from inner class
							SealedObject so_ticket = skpt.getEncrypytedticket();
							SealedObject so_session_key = skpt
									.getEncryptedSessionKey();

							// Getting IPb,Portb,Session Key
							Message.MessageSessionKey msk = msg.new MessageSessionKey();
							msk = (MessageSessionKey) (new Decrypter())
									.decrpyt(so_session_key, hashSharedKey);

							// session key Kab
							SecretKey session = msk.getSessionKeyWithReceiver();

							InetAddress ipReceiver = msk.getReceiver_ip();
							int portReceiver = msk.getReceiver_port();
							
							//add user to session
							user = new User(receiver, ipReceiver, portReceiver,
									null, null);
							
							this.sendUDPMessage(user, "hello", false, "chat");

							in.close();
							out.close();
							client_tcp_socket.close();

							//establish TCP connection to establish key between A and B
							//and for client to client authentication
							this.establishTCPConnection(user, message, session,
									so_ticket);
						}
					}
				}
			} catch (Exception e) {
				System.out.println("error in chat at client side");
			}
		} else {
			sendUDPMessage(user, message, true, "chatmessage");
		}
	}

	private void establishTCPConnection(User receiver, String message,
			SecretKey Kab, SealedObject so_ticket) {
			Gson gson = new Gson();

		try {	
			Socket connection = clntAsServersocket.accept();
			
			//verify ip address of receiver
			if (!connection.getInetAddress().equals(receiver.getIpaddress())){
				System.out.println("receiver does not match");
				connection.close();
				return;
			}

			BufferedReader in = new BufferedReader(new InputStreamReader(
					connection.getInputStream()));
			PrintWriter out = new PrintWriter(connection.getOutputStream(),
					true);
						
			// Generating a
			SecureRandom ranGen = new SecureRandom();
			int a = ranGen.nextInt((int) Math.pow(2, 8));
			
			// Encrypting a. Result : g^a mod p
			BigInteger DH_Sender = this.g.pow(a).mod(p);

			// encode Kab{g^a mod p}
			byte[] enc_dh_sender = (new Encrypter()).encrypt(
					DH_Sender.toByteArray(), Kab.getEncoded());

			// Generating c1
			BigInteger c1_chat = new BigInteger(128, ranGen);
			
			//generate iv for AES CBC 128 bit encryption
			byte[] iv=genIV();
			
			//encrypt iv with shared key
			byte[] enc_iv=new Encrypter().encrypt(iv, Kab.getEncoded());

			// adding ticket + encrypted diffie hellman contribution to message
			// class
			Message msg = new Message();
			Message.Chat1 chat1 = msg.new Chat1();
			chat1.setEnc_ticket(so_ticket);
			chat1.setEnc_new_key(enc_dh_sender);
			chat1.setC1(c1_chat);
			chat1.setIv(enc_iv);
			msg.setChat1(chat1);

			out.println(gson.toJson(msg, Message.class));

			// Receiving o_chat2
			String chat2 = in.readLine();
	
			Message o_msg_chat2 = (Message) gson.fromJson(chat2, Message.class);
			Chat2 o_chat2 = o_msg_chat2.getChat2();
			// Extracting DH of receiver Encrypted using session key
			BigInteger dh_receiver = new BigInteger(new Decrypter().decrpyt(
					o_chat2.getEnc_ack(), Kab.getEncoded()));

			// Generating chat_session_key
			BigInteger chat_session_key = dh_receiver.pow(a).mod(p);

			byte[] hash_chat_session_key = new HashGen().hash(chat_session_key
					.toByteArray());

			// Decrypting c1
			BigInteger verify_c1 = new BigInteger
			(new Decrypter().decrpyt(o_chat2.getEnc_c1(), hash_chat_session_key,iv));

			if (verify_c1.equals(c1_chat)) {
				receiver.setSharedKey(chat_session_key);
				
				//set iv for user
				receiver.setW(new BigInteger(iv));
				
				// Add user to hash map
				Client.registered_users.put(receiver.getUsername(), receiver);
				
				Client.user_ip.put(
						receiver.getIpaddress().toString()
								+ String.valueOf(receiver.getPort()),
						receiver.getUsername());

				// Encrypting c2 and enc_c2 using hash_chat_session_key
				byte[] enc_c2 = (new Encrypter()).encrypt(o_chat2.getC2()
						.toByteArray(), hash_chat_session_key,iv);
				Message.Chat3 chat3 = msg.new Chat3();
				chat3.setEnc_c2(enc_c2);
				msg.setChat3(chat3);

				out.println(gson.toJson(msg, Message.class));
				String str=new String(in.readLine());
				
				if(str.equalsIgnoreCase("ACK")){
					sendUDPMessage(receiver, message, true, "chatmessage");
				}else{
					System.out.println("connection cannot be established with reciver");
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private byte[] genIV(){
		// Generating IV
		SecureRandom rnd = new SecureRandom();
		byte[] iv = new byte[16];
		
		for (int i = 0; i < 16; i++) {
			iv[i] = (new BigInteger(8, rnd)).byteValue();
		}
		return iv;
	}
	
	//send UDP message to reciver
	private void sendUDPMessage(User receiver, String message,
			boolean to_encrpyt, String type) {
		
		//create message
		Message msg = new Message();
		Gson gson = new Gson();
		ChatMessage chat = msg.new ChatMessage(type);
		
		byte[] enc_message;
		byte[] hmac=null;
		
		//if message needs encryption then encrypt the message using shared key
		if (to_encrpyt) {
			//get key of receiver
			byte[] key = new HashGen().hash(receiver.getSharedKey()
					.toByteArray());
			//get iv of receiver
			 byte[] iv=receiver.getW().toByteArray();
			//encrypt message
			enc_message = new Encrypter().encrypt(message.getBytes(), key,iv);
			hmac=new Hmac().getHmac(enc_message, key);
		} else {
			enc_message = message.getBytes();
		}
		
		chat.setMessage(enc_message);
		chat.setHmac(hmac);
		msg.setChatmsg(chat);
		String data = gson.toJson(msg, Message.class);
		
		// send message
		try {
			DatagramPacket packet = new DatagramPacket(data.getBytes(),
					data.getBytes().length, receiver.getIpaddress(),
					receiver.getPort());
			Client.udp_socket.send(packet);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void handleListRequest() {
		Message msg;
		Gson gson = new Gson();
		try {
			//initialize TCP connection with server
			this.initializeTCPSocket();
			BufferedReader in = this.getIpStream();
			PrintWriter out = this.getOpStream();

			//send list message to server
			out.println("list");

			//receive nonce from server	
			msg = (Message) gson.fromJson(in.readLine(), Message.class);
			BigInteger N1 = msg.getLstmsg1().getN1();

			//encrpyt nonce using and send identity encrypted using server public key
			LstMessage2 msg2 = msg.new LstMessage2();
			BigInteger encN1 = new BigInteger(new RSA().encrypt(
					(new Encrypter().encrypt(N1.toByteArray(),
							this.hashSharedKey)), this.serverkey));
			msg2.setEnc_N1(encN1);
			
			//generate nonce 2
			BigInteger N2 = new NonceGen().genNonce();
			msg2.setN2(new BigInteger(new RSA().encrypt(N2.toByteArray(),
					this.serverkey)));
			msg2.setUsername(new RSA().encrypt(this.userid.getBytes(),
					this.serverkey));
			msg.setLstmsg2(msg2);
			out.println(gson.toJson(msg, Message.class));

			SealedObject obj = (SealedObject) (gson.fromJson(in.readLine(),
					SealedObject.class));
			msg = (Message) new Decrypter().decrpyt(obj, this.hashSharedKey);

			LstMessage3 msg3 = msg.getLstmsg3();

			//check if message is not replayed
			if (!(msg3.getN2().equals(N2))) {
				// error
				System.out.println("message is replayed");
				return;
			} else {
				//print list of all online users
				ArrayList<String> users = msg3.getUsers();
				System.out.println("Online Users:");
				for (String user : users) {
					System.out.println(user);
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("error occured while obtaining list from server");
		}
	}
	
	
	//hash generator
	public static byte[] hash(byte[] toHash) {
		MessageDigest sha;
		try {
			sha = MessageDigest.getInstance("SHA-256");
			toHash = sha.digest(toHash);

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return toHash;
	}

	//compute shared key between server and client
	private BigInteger computeSharedKey(BigInteger b, int u) {
		BigInteger W = new BigInteger(hash(this.password.getBytes()));

		// compute g raised to W mod p (g^w mod p)
		BigInteger gwp = this.g.modPow(W, this.p);

		// to get g raised to b

		BigInteger B = (b.subtract(gwp)).mod(this.p);

		// calculate (a + uW)
		BigInteger auW = W.multiply(BigInteger.valueOf(u)).add(
				BigInteger.valueOf(a));

		// calculate and return sharedkey
		return B.modPow(auW, this.p);
	}
	
	
	//convert object to byte array
	private Object byteArrayToObj(byte[] ba) {
		Object o = null;
		try {
			ByteArrayInputStream byte_Arr_IS = new ByteArrayInputStream(ba);
			ObjectInputStream obj_in_strm = new ObjectInputStream(byte_Arr_IS);
			o = obj_in_strm.readObject();
			obj_in_strm.close();
			byte_Arr_IS.close();

		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (ClassNotFoundException e2) {
			e2.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return o;
	}

	//get private key of server
	public static PrivateKey getPrivateKey(String filename) {
		// reading Private key object from private key file
		ObjectInputStream inputStream = null;
		PrivateKey privateKey = null;

		try {
			inputStream = new ObjectInputStream(new FileInputStream(filename));
			privateKey = (PrivateKey) inputStream.readObject();
			inputStream.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return privateKey;
	}

	//read DH parameters from file
	private void getDHKey() {
		GenerateDHParam dh = (GenerateDHParam) readObject("dh.param");
		this.g = dh.getG();
		this.p = dh.getP();
		SecureRandom ranGen1 = new SecureRandom();
		this.a = ranGen1.nextInt(1000);
		A = g.pow(a).mod(p);
	}

	//read object from file
	public Object readObject(String filename) {
		ObjectInputStream inputStream = null;
		Object dh = null;

		try {
			inputStream = new ObjectInputStream(new FileInputStream(filename));
			dh = inputStream.readObject();
			inputStream.close();
		} catch (Exception e) {
			System.out.println("error occured while reading object from object file");
			System.out.println("Client side config file not configured properly");
			System.exit(0);
		}
		return dh;
	}

	//read public key from file
	public static PublicKey getPublicKey(String filename) {
		// reading Public key object from public key file
		ObjectInputStream inputStream = null;
		PublicKey publicKey = null;

		try {
			inputStream = new ObjectInputStream(new FileInputStream(filename));
			publicKey = (PublicKey) inputStream.readObject();
			inputStream.close();
		} catch (Exception e) {
			System.out.println("error occured while reading public key of server");
			System.exit(0);
		}
		return publicKey;
	}
	
	//read input file
	public String readFile(String filename) {
		// reading input file
		File f1 = new File(filename);
		FileInputStream fios = null;
		BufferedReader br = null;
		String s = "";
		String content = "";
		try {
			content = new String();
			fios = new FileInputStream(f1);
			br = new BufferedReader(new InputStreamReader(fios));
			while ((s = br.readLine()) != null)
				content = content + s + "\n";
			br.close();
		} catch (Exception e) {
			System.out.println("error while reading the input file");
			System.exit(1);
		}
		return content;
	}

	public static void setPort(int port) {
		Client.port = port;
	}

	public int getPort() {
		return Client.port;
	}

	public void setServer_port(int server_port) {
		this.server_port = server_port;
	}

	public int getServer_port() {
		return server_port;
	}

	public static void setRegistered_users(Map<String, User> registered_users) {
		Client.registered_users = registered_users;
	}

	public static Map<String, User> getRegistered_users() {
		return registered_users;
	}

	public static void setUdp_socket(DatagramSocket udp_socket) {
		Client.udp_socket = udp_socket;
	}

	public static DatagramSocket getUdp_socket() {
		return udp_socket;
	}

	public byte[] getHashSharedKey() {
		return hashSharedKey;
	}

	public BigInteger getG() {
		return g;
	}

	public BigInteger getP() {
		return p;
	}

	public String getUserid() {
		return userid;
	}

	public static void setUser_ip(Map<String, String> user_ip) {
		Client.user_ip = user_ip;
	}

	public static Map<String, String> getUser_ip() {
		return user_ip;
	}

}