package client;

import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.InetAddress;
import java.util.Scanner;

public class ServerConfig implements Serializable{

	private static final long serialVersionUID = 1L;
	private InetAddress ipaddress;
	private int udp_port;
	private int tcp_port;
	
	public InetAddress getIpaddress() {
		return ipaddress;
	}
	
	public int getPort() {
		return udp_port;
	}
	
	public int getTcp_port() {
		return tcp_port;
	}
	
	public static void main(String arg[]){
		ServerConfig sc = new ServerConfig();
		Scanner read = new Scanner(System.in);
		System.out.println("Enter Server IP address");
		try{
		sc.ipaddress=InetAddress.getByName(read.nextLine());
		System.out.println("enter server UDP port number");
		sc.udp_port=read.nextInt();
		System.out.println("enter server TCP port number");
		sc.tcp_port=read.nextInt();
		sc.writeObject("Server.conf");
		}catch(Exception e){
			System.out.println("Error in IP address/Port Number");
		}
	}
	
	public void writeObject(String filename) {
	    //writing object into output file
	    ObjectOutputStream obj;
	    try {
	      obj = new ObjectOutputStream(new FileOutputStream(filename));
	      obj.writeObject(this);
	      obj.close();
	      System.out.println("Server Configured successfully");
	    } catch (Exception e) {
	      // TODO Auto-generated catch block
	      System.out.println("error occured while writing object into output file");
	    }
	 }

}
