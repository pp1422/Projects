package client;

import java.math.BigInteger;
import java.net.InetAddress;

public class User {
	private String username;
	private InetAddress ipaddress;
	private int port;
	private BigInteger W; //g^W mod p from UserNamePassWord
	private BigInteger sharedKey;
	
	public User(String username, InetAddress ipAddress, int portNumber,
			BigInteger w, BigInteger key) {
		this.username=username;
		this.ipaddress=ipAddress;
		this.port=portNumber;
		this.W=w;
		this.sharedKey=key;
	}
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	
	
	public void setIpaddress(InetAddress ipaddress) {
		this.ipaddress = ipaddress;
	}
	public InetAddress getIpaddress() {
		return ipaddress;
	}
	public void setPort(int port) {
		this.port = port;
	}
	public int getPort() {
		return port;
	}
	public void setW(BigInteger w) {
		W = w;
	}
	public BigInteger getW() {
		return W;
	}
	public BigInteger getSharedKey() {
		return sharedKey;
	}
	public void setSharedKey(BigInteger sharedKey) {
		this.sharedKey = sharedKey;
	}
	
}
