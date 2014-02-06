package client;

import java.io.Serializable;
import java.math.BigInteger;
import java.net.InetAddress;
import java.util.ArrayList;

import javax.crypto.SealedObject;
import javax.crypto.SecretKey;

@SuppressWarnings("serial")
public class Message implements Serializable {
		private Message1 msg1;
		private Message2 msg2;
		private Message3 msg3;
		private Message4 msg4;
		private Message5 msg5;
		private Message6 msg6;
		private LstMessage1 lstmsg1;
		private LstMessage2 lstmsg2;
		private LstMessage3 lstmsg3;
		private ChatMessage chatmsg;
		private MessageRequestChat rqChat;
		private SessionKeyPlusTicket skpt;    // sharedkey for send + ticket for receiver + digital signature
		private Enc_Intial_Chaat eic;
		private MessageTicket msgTic;      //contents of the ticket and not the encrypted ticket
		private MessageSessionKey sharedKeyPlus; 
		private SessionKeyTicketSign skts;
		private Chat1 chat1;
		private Chat2 chat2;
		private Chat3 chat3;
		private String type;
				
		public MessageRequestChat getRqChat() {
			return rqChat;
		}

		public void setRqChat(MessageRequestChat rqChat) {
			this.rqChat = rqChat;
		}

		
		public SessionKeyPlusTicket getSkpt() {
			return skpt;
		}

		public void setSkpt(SessionKeyPlusTicket skpt) {
			this.skpt = skpt;
		}

		public Enc_Intial_Chaat getEic() {
			return eic;
		}

		public void setEic(Enc_Intial_Chaat eic) {
			this.eic = eic;
		}

		public MessageTicket getMsgTic() {
			return msgTic;
		}

		public void setMsgTic(MessageTicket msgTic) {
			this.msgTic = msgTic;
		}

		public SessionKeyTicketSign getSkts() {
			return skts;
		}

		public void setSkts(SessionKeyTicketSign skts) {
			this.skts = skts;
		}

		public Chat1 getChat1() {
			return chat1;
		}

		public void setChat1(Chat1 chat1) {
			this.chat1 = chat1;
		}

		public Chat2 getChat2() {
			return chat2;
		}

		public void setChat2(Chat2 chat2) {
			this.chat2 = chat2;
		}

		public Chat3 getChat3() {
			return chat3;
		}

		public void setChat3(Chat3 chat3) {
			this.chat3 = chat3;
		}

	
		public class Message1{
			private byte[] username;
			private BigInteger A;
			private String type="login.msg1";
			
			public Message1(){
				Message.this.type=this.type;
			}
			
			public byte[] getUsername() {
				return username;
			}
			public void setUsername(byte[] username) {
				this.username = username;
			}
			public BigInteger getA() {
				return A;
			}
			public void setA(BigInteger a) {
				A = a;
			}
		
			public String getType() {
				return type;
			}
		}
		
		public class Message2{
			private byte[] puzzle;
			private String type="login.msg2";
			
			public Message2(){
				Message.this.type=this.type;
			}

			public void setPuzzle(byte[] puzzle) {
				this.puzzle = puzzle;
			}

			public byte[] getPuzzle() {
				return puzzle;
			}
		}
		
		public class Message3{
			private BigInteger puzzle_response;
			private String type="login.msg2";
			
			public Message3(){
				Message.this.type=this.type;
			}

			public void setPuzzle_response(BigInteger puzzle_response) {
				this.puzzle_response = puzzle_response;
			}

			public BigInteger getPuzzle_response() {
				return puzzle_response;
			}
		}
		
		public class Message4{
			private BigInteger B;
			private int u;
			private BigInteger c1;
			private String type="login.msg4";
			
			public Message4(){
				Message.this.type=this.type;
			}
			
			public int getU() {
				return u;
			}
			public void setU(int u) {
				this.u = u;
			}
			public BigInteger getC1() {
				return c1;
			}
			public void setC1(BigInteger c1) {
				this.c1 = c1;
			}
			public void setB(BigInteger b) {
				B = b;
			}
			public BigInteger getB() {
				return B;
			}
			public void setType(String type) {
				this.type = type;
			}
			public String getType() {
				return type;
			}
		}
		
		public class Message5{
			private BigInteger enc_c1;
			private BigInteger c2;
			private String type="login.msg5";
			
			public Message5(){
				Message.this.type=this.type;
			}
			
			public void setEnc_c1(BigInteger enc_c1) {
				this.enc_c1 = enc_c1;
			}
			public BigInteger getEnc_c1() {
				return enc_c1;
			}
			public void setC2(BigInteger c2) {
				this.c2 = c2;
			}
			public BigInteger getC2() {
				return c2;
			}
			public void setType(String type) {
				this.type = type;
			}
			public String getType() {
				return type;
			}
		}
		
		public class Message6{
			private String status;
			private BigInteger enc_c2;
			private String type="login.msg6";
			
			public Message6(){
				Message.this.type=this.type;
			}
			
			public void setEnc_c2(BigInteger enc_c2) {
				this.enc_c2 = enc_c2;
			}

			public BigInteger getEnc_c2() {
				return enc_c2;
			}

			public void setType(String type) {
				this.type = type;
			}

			public String getType() {
				return type;
			}

			public String getStatus() {
				return status;
			}

			public void setStatus(String status) {
				this.status = status;
			}
		}
		
		public class LstMessage1 implements Serializable{
			private BigInteger N1;
			private String type="lstmsg1";
			
			public LstMessage1(){
				Message.this.type=this.type;
			}

			public void setN1(BigInteger n1) {
				N1 = n1;
			}

			public BigInteger getN1() {
				return N1;
			}
		}

		public class LstMessage2 implements Serializable{
			private byte[] username;
			private BigInteger N2;
			private BigInteger enc_N1;
			private String type="lstmsg2";
			
			public LstMessage2(){
				Message.this.type=this.type;
			}

			public byte[] getUsername() {
				return username;
			}

			public void setUsername(byte[] username) {
				this.username = username;
			}

			public BigInteger getN2() {
				return N2;
			}

			public void setN2(BigInteger n2) {
				N2 = n2;
			}

			public BigInteger getEnc_N1() {
				return enc_N1;
			}

			public void setEnc_N1(BigInteger enc_N1) {
				this.enc_N1 = enc_N1;
			}

			public String getType() {
				return type;
			}

			public void setType(String type) {
				this.type = type;
			}
		}
		
		public class LstMessage3 implements Serializable{
			private BigInteger N2;
			private ArrayList<String> users;
			private String type="lstmsg3";
			
			public LstMessage3(){
				Message.this.type=this.type;
			}
			
			public void setUsers(ArrayList<String> users) {
				this.users = users;
			}
			public ArrayList<String> getUsers() {
				return users;
			}
			public void setN2(BigInteger n2) {
				N2 = n2;
			}
			public BigInteger getN2() {
				return N2;
			} 
		}
		
		public class ChatMessage implements Serializable{
			private byte[] message;
			private String type="chat";
			private byte[] hmac;
			
			public ChatMessage(){
				Message.this.type=this.type;
			}
			public ChatMessage(String type){
				Message.this.type=type;
			}

			public void setMessage(byte[] message) {
				this.message = message;
			}

			public byte[] getMessage() {
				return message;
			}
			public void setHmac(byte[] hmac) {
				this.hmac = hmac;
			}
			public byte[] getHmac() {
				return hmac;
			}
		}
		
		public class Chat3{
			private byte[] enc_c2;

			public byte[] getEnc_c2() {
				return enc_c2;
			}

			public void setEnc_c2(byte[] enc_c2) {
				this.enc_c2 = enc_c2;
			}
			
		}
		public class SessionKeyTicketSign{
			private byte[] signature;
			private byte[] byteArrayOfObject;
			public byte[] getSignature() {
				return signature;
			}
			public void setSignature(byte[] signature) {
				this.signature = signature;
			}
			public byte[] getByteArrayOfObject() {
				return byteArrayOfObject;
			}
			public void setByteArrayOfObject(byte[] byteArrayOfObject) {
				this.byteArrayOfObject = byteArrayOfObject;
			}
		}
		
		public class MessageRequestChat implements Serializable{
			private byte[] enc_receiver_name;
			private byte[] enc_userName;
			private String type="chatrequest";
				
			public MessageRequestChat(){
				Message.this.type=this.type;
			}
			
			public byte[] getEnc_userName() {
				return enc_userName;
			}
			public void setEnc_userName(byte[] enc_userName) {
				this.enc_userName = enc_userName;
			}
			public byte[] getEnc_receiver_name() {
				return enc_receiver_name;
			}
			public void setEnc_receiver_name(byte[] enc_receiver_name) {
				this.enc_receiver_name = enc_receiver_name;
			}
		}
		
		public class Enc_Intial_Chaat{
			private byte[] enc_initial;

			public byte[] getEnc_initial() {
				return enc_initial;
			}

			public void setEnc_initial(byte[] enc_initial) {
				this.enc_initial = enc_initial;
			}
		}
		
		public class Chat2{
			private byte[] enc_ack;
			private byte[] enc_c1;
			private BigInteger c2;

			public byte[] getEnc_c1() {
				return enc_c1;
			}

			public void setEnc_c1(byte[] enc_c1) {
				this.enc_c1 = enc_c1;
			}

			public byte[] getEnc_ack() {
				return enc_ack;
			}

			public void setEnc_ack(byte[] enc_ack) {
				this.enc_ack = enc_ack;
			}

			public BigInteger getC2() {
				return c2;
			}

			public void setC2(BigInteger c2) {
				this.c2 = c2;
			}
		}
		public class Chat1{
			private byte[] enc_new_key;
			private SealedObject enc_ticket;
			private BigInteger c1;
			private byte[] iv;

			public byte[] getEnc_new_key() {
				return enc_new_key;
			}

			public void setEnc_new_key(byte[] enc_new_key) {
				this.enc_new_key = enc_new_key;
			}

			public SealedObject getEnc_ticket() {
				return enc_ticket;
			}

			public void setEnc_ticket(SealedObject enc_ticket) {
				this.enc_ticket = enc_ticket;
			}

			public BigInteger getC1() {
				return c1;
			}

			public void setC1(BigInteger c1) {
				this.c1 = c1;
			}

			public void setIv(byte[] iv) {
				this.iv = iv;
			}

			public byte[] getIv() {
				return iv;
			}
		}
		public MessageSessionKey getSharedKeyPlus() {
			return sharedKeyPlus;
		}

		public void setSharedKeyPlus(MessageSessionKey sharedKeyPlus) {
			this.sharedKeyPlus = sharedKeyPlus;
		}

		
	
		public class MessageTicket implements Serializable{
			private InetAddress senderIp;
			private int senderPort;
			private String sender;
			private String intendedReceiver;
			private SecretKey sessionKey;

			
			public InetAddress getSenderIp() {
				return senderIp;
			}

			public void setSenderIp(InetAddress senderIp) {
				this.senderIp = senderIp;
			}

			public int getSenderPort() {
				return senderPort;
			}

			public void setSenderPort(int senderPort) {
				this.senderPort = senderPort;
			}

			public String getSender() {
				return sender;
			}

			public void setSender(String sender) {
				this.sender = sender;
			}

			public SecretKey getSessionKey() {
				return sessionKey;
			}

			public void setSessionKey(SecretKey sessionKey) {
				this.sessionKey = sessionKey;
			}

			public String getIntendedReceiver() {
				return intendedReceiver;
			}

			public void setIntendedReceiver(String intendedReceiver) {
				this.intendedReceiver = intendedReceiver;
			}
			
		}
		public class SessionKeyPlusTicket implements Serializable{
			private SealedObject encrypytedticket;
			private SealedObject encryptedSessionKey;
			
			public SealedObject getEncrypytedticket() {
				return encrypytedticket;
			}
			public void setEncrypytedticket(SealedObject encrypytedticket) {
				this.encrypytedticket = encrypytedticket;
			}
			public SealedObject getEncryptedSessionKey() {
				return encryptedSessionKey;
			}
			public void setEncryptedSessionKey(SealedObject encryptedSessionKey) {
				this.encryptedSessionKey = encryptedSessionKey;
			}
			
			
		}
		public class Ticket{
			private BigInteger sessionKeyWithSender;
			private InetAddress sender_ip;
			int sender_port;
			String sender;
			
			public BigInteger getSessionKeyWithSender() {
				return sessionKeyWithSender;
			}
			public void setSessionKeyWithSender(BigInteger sessionKeyWithSender) {
				this.sessionKeyWithSender = sessionKeyWithSender;
			}
			public InetAddress getSender_ip() {
				return sender_ip;
			}
			public void setSender_ip(InetAddress sender_ip) {
				this.sender_ip = sender_ip;
			}
			public int getSender_port() {
				return sender_port;
			}
			public void setSender_port(int sender_port) {
				this.sender_port = sender_port;
			}
			public String getSender() {
				return sender;
			}
			public void setSender(String sender) {
				this.sender = sender;
			}			
		}
		
		public class MessageSessionKey implements Serializable{
			private SecretKey sessionKey;
			private InetAddress receiver_ip;
			private int receiver_port;
			
			public SecretKey getSessionKeyWithReceiver() {
				return sessionKey;
			}
			public void setSessionKeyWithReceiver(SecretKey sessionKeyWithReceiver) {
				this.sessionKey = sessionKeyWithReceiver;
			}
			public InetAddress getReceiver_ip() {
				return receiver_ip;
			}
			public void setReceiver_ip(InetAddress receiver_ip) {
				this.receiver_ip = receiver_ip;
			}
			public int getReceiver_port() {
				return receiver_port;
			}
			public void setReceiver_port(int receiver_port) {
				this.receiver_port = receiver_port;
			}
		}
		
		public Message1 getMsg1() {
			return msg1;
		}

		public void setMsg1(Message1 msg1) {
			this.msg1 = msg1;
		}

		public Message2 getMsg2() {
			return msg2;
		}

		public void setMsg2(Message2 msg2) {
			this.msg2 = msg2;
		}

		public Message3 getMsg3() {
			return msg3;
		}

		public void setMsg3(Message3 msg3) {
			this.msg3 = msg3;
		}

		public Message4 getMsg4() {
			return msg4;
		}

		public void setMsg4(Message4 msg4) {
			this.msg4 = msg4;
		}

		public Message5 getMsg5() {
			return msg5;
		}

		public void setMsg5(Message5 msg5) {
			this.msg5 = msg5;
		}

		public Message6 getMsg6() {
			return msg6;
		}

		public void setMsg6(Message6 msg6) {
			this.msg6 = msg6;
		}

		public String getType() {
			return type;
		}

		public void setType(String type) {
			this.type = type;
		}

		public void setLstmsg1(LstMessage1 lstmsg1) {
			this.lstmsg1 = lstmsg1;
		}

		public LstMessage1 getLstmsg1() {
			return lstmsg1;
		}

		public void setLstmsg2(LstMessage2 lstmsg2) {
			this.lstmsg2 = lstmsg2;
		}

		public LstMessage2 getLstmsg2() {
			return lstmsg2;
		}

		public void setLstmsg3(LstMessage3 lstmsg3) {
			this.lstmsg3 = lstmsg3;
		}

		public LstMessage3 getLstmsg3() {
			return lstmsg3;
		}

		public void setChatmsg(ChatMessage chatmsg) {
			this.chatmsg = chatmsg;
		}

		public ChatMessage getChatmsg() {
			return chatmsg;
		}

	}
