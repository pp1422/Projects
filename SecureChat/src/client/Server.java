package client;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Map;
import java.util.HashMap;
import java.util.Scanner;

import javax.imageio.spi.RegisterableService;

import client.Message.Message1;

import com.google.gson.Gson;

public class Server{
	private DatagramSocket serverSocket; //server socket
	private BigInteger g; //server DH g
	private BigInteger p; //server DH p
	private int server_port; // server UDP port
	private int server_tcp_port; //server tcp port
	private InetAddress serverIPAddr; 
	private static Map<String, User> registered_users; //list of all online users
	private static ServerSocket tcpServerSocket; //tcp server socket
	private PrivateKey serverPrivateKey; //private key of server

	public static Map<String, User> getRegistered_users() {
		return registered_users;
	}

	public BigInteger getP() {
		return p;
	}

	public static void main(String arg[]) {
		ServerTCPListener obj=null;
		Server server = new Server();
		
		try {
			
			//retrieve server network details from config file
			server.getServerDetails();

			// create server socket for given server port
			server.serverSocket = new DatagramSocket(server.server_port);

			// TCP socket
			tcpServerSocket = new ServerSocket(server.server_tcp_port);

			System.out.println("Server Initialized...");

			//initialize registered users
			Server.registered_users = Collections.synchronizedMap(new HashMap<String, User>());
			
			// Read DH parameter from file
			GenerateDHParam dh = (GenerateDHParam) readObject("dh.param");
			server.g = dh.getG();
			server.p = dh.getP();
			
			//start TCP listener for server which will accept client connections
			obj = new ServerTCPListener(tcpServerSocket, server);
			obj.start();

			System.out.println("Welcome to my chat group!!! Have Fun!!!!");
			
			server.readFromConsole();

		} catch (Exception e) {
			System.out.println("error in server connection");
		} finally {
			obj.setAliveFalse();
			server.closeTCPSocket();
		}
	} // end main

	private void closeTCPSocket() {
		try {
			tcpServerSocket.close();

		} catch (IOException e) {
			System.out.println("cannot close server socket");
		}
	}

	//Continuously read from console
	private void readFromConsole() {
		Scanner sc;
		while (true) {
			sc = new Scanner(System.in);
			if (sc.nextLine().equals("bye")) {
				this.closeTCPSocket();
				break;
			}
		}
		sc.close();
	}

	public BigInteger getG() {
		return g;
	}

	public int getServer_port() {
		return server_port;
	}

	public PrivateKey getServerPrivateKey() {
		return serverPrivateKey;
	}

	//retrieve server details from file
	private void getServerDetails() {
		ServerConfig sc = (ServerConfig) readObject("Server.conf");
		this.serverIPAddr =sc.getIpaddress();
		this.server_port = sc.getPort(); // Get Server's UDP port
		this.server_tcp_port = sc.getTcp_port(); //Get Server's tcp port
		this.serverPrivateKey = getPrivateKey("server-private.key");  // Get Server's Private Key
	}

	//read object from file
	public static Object readObject(String filename) {
		ObjectInputStream inputStream = null;
		Object oj = null;

		try {
			inputStream = new ObjectInputStream(new FileInputStream(filename));
			oj = inputStream.readObject();
			inputStream.close();
		} catch (Exception e) {
			System.out.println("error occured while reading object from object file");
		}
		return oj;
	}

	public static PrivateKey getPrivateKey(String filename) {
		// reading Private key object from private key file
		ObjectInputStream inputStream = null;
		PrivateKey privateKey = null;

		try {
			inputStream = new ObjectInputStream(new FileInputStream(filename));
			privateKey = (PrivateKey) inputStream.readObject();
			inputStream.close();
		} catch (Exception e) {
			System.out.println("cannot retrieve private key");
		}
		return privateKey;
	}

	//hash SHA-256
	public static byte[] hash(byte[] toHash) {
		MessageDigest sha;
		try {
			sha = MessageDigest.getInstance("SHA-256");
			toHash = sha.digest(toHash);
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Hashing Algorithm is incorrect");
		}
		return toHash;
	}

	public DatagramSocket getServerSocket() {
		return serverSocket;
	}
}
