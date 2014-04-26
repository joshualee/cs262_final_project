package edu.harvard.cs262.crypto;

import java.math.BigInteger;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.util.List;
import java.util.LinkedList;
import java.util.ListIterator;
import java.util.Map;
import java.util.Set;
import java.util.Random;
import java.util.Scanner;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class DHCryptoClient implements CryptoClient {
	private final int VERBOSE;
	private String name;
	private CryptoServer server;
	private Map<String, CryptoCipher> ciphers;
	private Map<String, CryptoMessage> sessions;
	private Map<ClientPair, List<CryptoMessage>> messages;
	
	/**
	 * 
	 * 
	 * @param s the string to print
	 * @param threshold the verbosity level
	 */
	private void verbosePrint(String s, int threshold) {
		if (VERBOSE >= threshold) {
			System.out.println(s);	
		}
	}
	
	public DHCryptoClient(String name, CryptoServer server) {
		VERBOSE = 1;
		this.name = name;
		this.server = server;
		this.ciphers = new ConcurrentHashMap<String, CryptoCipher>();
		this.sessions = new ConcurrentHashMap<String, CryptoMessage>();
		this.messages = new ConcurrentHashMap<ClientPair, List<CryptoMessage>>();
	}

	@Override
	public void recvMessage(String from, String to, CryptoMessage m) throws InterruptedException {
		System.out.println(String.format("(%s) recvMessage(%s, %s, m)", name, from, to));
		
		String plaintext;
		
		// add received message to appropriate list
		ClientPair myPair = new ClientPair(from, to);
		if(messages.containsKey(myPair)){
			List<CryptoMessage> messageList = messages.get(myPair);
			messageList.add(m); 
		}
		else{
			List<CryptoMessage> messageList = new LinkedList<CryptoMessage>();
			messageList.add(m);
			messages.put(myPair,messageList);
		}
		
		if (m.hasSessionID() && to.equals(name)) {
			System.out.println(String.format("(%s) got message with sid %s", name, m.getSessionID()));
			
			String sid = m.getSessionID();
			/*
			 * If there is already a waiting message, wait for
			 * message to be processed before adding to queue.
			 */
			synchronized(sessions) {
				while (sessions.containsKey(sid)) {
					verbosePrint(String.format("(%s) warning: session " + sid + " already has a waiting message", name), 1);
					sessions.wait();
				}
				sessions.put(sid, m);
				sessions.notifyAll();
			}
			System.out.println(String.format("(%s) done recvMessage", name));
			return;
		}
		
		if (!m.isEncrypted()) {
			plaintext = m.getPlainText();
		}
		else {
			CryptoCipher key = ciphers.get(from);
			if (key != null) {
				plaintext = key.decrypt(m);
				
				if (!plaintext.equals(m.getPlainText())) {
					System.out.println("Warning: plaintext does not match original message");
				}
				verbosePrint(from + " (ciphertext): " + m.getCipherText(), 0);	
			}
			else {
				plaintext = m.getCipherText();
			}
		}
		
		System.out.println(String.format("(%s) %s-%s: %s", name, from, to, plaintext));
	}
	
	public CryptoMessage waitForMessage(String sid) throws RemoteException, InterruptedException {
		CryptoMessage m;
		
		synchronized(sessions) {
			while (!sessions.containsKey(sid)) {
				System.out.println(String.format("(%s) waiting for session: %s", name, sid));
				sessions.wait();
			}
			System.out.println(String.format("(%s) got message for session: %s", name, sid));
			m = sessions.remove(sid);
			sessions.notifyAll();
		}
		
		return m;
	}
	
	public void recvSecureChannel(String counterParty, KeyExchangeProtocol kx, CryptoCipher cipher) throws RemoteException, InterruptedException, ClientNotFound {
		try{
			if (ciphers.containsKey(counterParty)) {
				verbosePrint("Warning: key for " + counterParty + " already exists", 1);
			}
			
			CryptoKey key = kx.reciprocate(this, counterParty);
			cipher.setKey(key);
			ciphers.put(counterParty, cipher);
		}catch (ClientNotFound e) {
			System.out.println("\nError: " + e.getErrorMessage());
		}	
	}
	
	public void initSecureChannel(final String counterParty, final KeyExchangeProtocol kx, final CryptoCipher cipher) throws RemoteException, ClientNotFound, InterruptedException {
		try{
			System.out.println(String.format("%s: initSecureChannel", name));
			
			if (ciphers.containsKey(counterParty)) {
				verbosePrint("Warning: key for " + counterParty + " already exists", 1);
			}
			
			// indirectly invoke the counterpart of the key exchange on remote client
			
			Helpers.doAsync(new Runnable() { public void run() {
				try {
					server.relaySecureChannel(name, counterParty, kx, cipher);
				}catch (ClientNotFound e) {
					System.out.println("\nError: " + e.getErrorMessage());
				}catch (Exception e) {
					e.printStackTrace();
				}
			} });
			
			System.out.println(String.format("%s: about to kx.initiate", name));
			CryptoKey key = kx.initiate(this, counterParty);
			System.out.println(String.format("%s: finished kx.initiate", name));
			cipher.setKey(key);
			ciphers.put(counterParty, cipher);
		}catch (ClientNotFound e) {
			System.out.println("\nError: " + e.getErrorMessage());
		}	
	}

	@Override
	public boolean ping() {
		// console interactions are difficult if pinged message keeps printing
		// System.out.println("pinged");
		return true;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override 
	public void setName(String name) {
		this.name = name;
	}

	@Override
	public Map<ClientPair, List<CryptoMessage>> getMessages() {
		return this.messages;
	}

	@Override
	public void sendMessage(String to, String text, String sid) throws RemoteException, ClientNotFound, InterruptedException {
		try{
			System.out.println(String.format("(%s) sending message to %s with session %s: %s", name, to, sid, text));
			CryptoMessage m = new CryptoMessage(text, sid);
			if (sid.length() > 0) {
				m.setSessionID(sid);	
			}
			
			server.sendMessage(name, to, m);
		}catch (ClientNotFound e) {
			System.out.println("\nError: " + e.getErrorMessage());
		}	
	}
	
	// To do: hangs if Client 'to' is unregistered
	public void sendEncryptedMessage(String to, String text, String sid) throws RemoteException, ClientNotFound, InterruptedException {
		try{
			CryptoCipher c = ciphers.get(to);
			if (c == null) {
				DiffieHellman dh = new DiffieHellman();
				ElGamalCipher eg = new ElGamalCipher();
				initSecureChannel(to, dh, eg);
				sendEncryptedMessage(to, text, sid);
				return;
			}
			
			CryptoMessage m = c.encrypt(text);
			m.setSessionID(sid);
			server.sendMessage(name, to, m);
		}catch (ClientNotFound e) {
			System.out.println("\nError: " + e.getErrorMessage());
		}	
	}
	

	@Override
	public void eavesdrop(String victim) throws RemoteException, ClientNotFound {
		try{
			server.eavesdrop(name, victim);
		}catch (ClientNotFound e) {
			System.out.println("\nError: " + e.getErrorMessage());
		}	
	}

	@Override
	public void stopEavesdrop(String victim) throws RemoteException, ClientNotFound {
		try{
			server.stopEavesdrop(name, victim);
		
		}catch (ClientNotFound e) {
			System.out.println("\nError: " + e.getErrorMessage());
		}		
	}

	// does this need to throw ClientNotFound?	
	public void eVote(EVote evote) throws RemoteException, ClientNotFound, InterruptedException {
		Random rand = new Random();
		String sid = evote.id.toString();
		Scanner scan = new Scanner(System.in);
		
		/*
		 * EVote phase one: 
		 * client receives a ballot from the server
		 */
		System.out.println("Initiating e-vote:");
		System.out.print(String.format("Ballot (%s): ", sid));
		System.out.println(evote.ballot + "\n");
		
		//int yay_or_nay = rand.nextInt(2);
		int yay_or_nay;
		String clientVote = "";
	
		System.out.println("Vote [y\\n]:");
		System.out.println("y: vote in favor");
		System.out.println("n: vote against");
		
		while (true) {
			clientVote = scan.nextLine();
			if (clientVote.equals("y")) {
				System.out.println("You voted in favor");
				yay_or_nay = 1;
				break;
			}
			else if (clientVote.equals("n")) {
				System.out.println("You voted against");
				yay_or_nay = 0;
				break;
			}
			else {
				System.out.print("try again [y\n]: ");
			}
		}
		
		System.out.println("Tallying vote...");
		
		
//		int yay_or_nay = rand.nextInt(2);
		
		/*
		 * EVote phase two: 
		 * each client generates own secret key and sends to server
		 */
		BigInteger sk_i = (new BigInteger(evote.BITS, rand)).mod(evote.p);
		BigInteger pk_i = evote.g.modPow(sk_i, evote.p);
		CryptoMessage phaseTwo = new CryptoMessage(pk_i.toString(), sid);
		server.recvMessage(getName(), server.getName(), phaseTwo);
		CryptoMessage pkMsg = waitForMessage(sid);
		
		/*
		 * EVote phase four:
		 * client decides vote and encrypts using ElGamal 
		 */
		
		// since for now we only do the encryption phase,
		// we only have to set the public key
		ElGamalCipher EGCipher = new ElGamalCipher();
		DHTuple	dht = new DHTuple(evote.p, evote.g, 
				new BigInteger(pkMsg.getPlainText()));

		CryptoKey publicKey = new CryptoKey(null, dht, evote.BITS);
		EGCipher.setKey(publicKey);
		
		// TODO: vote input instead of random
		BigInteger vote = evote.g.pow(yay_or_nay).mod(evote.p);
		// TODO: encrypt vote directly since it is already a number... instead of
		// doing the string manipulation
		CryptoMessage encryptedVote = EGCipher.encrypt(vote.toString());
		encryptedVote.setSessionID(sid);
		
		// TODO: send tag with server message, so clients know what they are seeing when eaves dropping
		// TODO: store server name
		server.recvMessage(name, server.getName(), encryptedVote);
		
		/*
		 * EVote phase 6:
		 * receive combined cipher text from server
		 * let (c1, c2) = cipher text
		 * compute (c1)^(sk_i) and send to server
		 */
		
		CryptoMessage combinedCipher = waitForMessage(sid);
		BigInteger c1 = (BigInteger) combinedCipher.getEncryptionState();
		BigInteger c2 = new BigInteger(combinedCipher.getPlainText());
		BigInteger encryptedC1 = c1.modPow(sk_i, evote.p);
		
		server.recvMessage(name, server.getName(), 
				new CryptoMessage(encryptedC1.toString(), sid));
		/*
		 * EVote phase 8:
		 * clients use decodingKey to decode message 
		 */
		
		CryptoMessage decodingKeyMsg = waitForMessage(sid);
		BigInteger decodingKey = new BigInteger(decodingKeyMsg.getPlainText());
		BigInteger voteResult = c2.divide(decodingKey).mod(evote.p);
		
		int numVoters = evote.voters.size();
		
		System.out.println(String.format("Ballot (%s): %s yes, %d no", 
			numVoters, voteResult, numVoters - voteResult.intValue()));
	}
	
	public static void main(String args[]) {
		if (args.length < 3) {
			System.err.println("usage: java DHCryptoClient rmiHost rmiPort serverName");
			System.exit(1);
		}
		
		// args[0]: IP (registry)
		// args[1]: Port (registry)
		// args[2]: Server name
		
		String rmiHost = args[0];
		int rmiPort = Integer.parseInt(args[1]);
		String serverName = args[2];
		
		if (System.getSecurityManager() == null) {
			System.setSecurityManager(new SecurityManager());
		}
		
		try {
			String clientName = "";
			Registry registry = LocateRegistry.getRegistry(rmiHost, rmiPort);
			CryptoServer server = (CryptoServer) registry.lookup(serverName);
			CryptoClient myClient = new DHCryptoClient(clientName, server);
			CryptoClient myClientSer = ((CryptoClient)UnicastRemoteObject.exportObject(myClient, 0));

      //Create new Scanner
      Scanner scan = new Scanner(System.in);
      			
			// boolean to keep track of whether the Client is registered
      boolean reg = false;

      //Menu
      String menu = "\n====== Help Menu ======\nu: unregister\nc: see list of registered clients\nm: send message to client"
      	+ "\ne: listen to a client's communications\ns: stop listening to a client's communications\nr: see list of all received messages"
      	+ "\nh: display this menu";

			while(true){
				
				// make client register before it can do anything else
				while(!reg){
					System.out.print("Enter your name: ");
					clientName = scan.nextLine();							
					myClient.setName(clientName);
					
					if(server.registerClient(myClientSer)){
						System.out.println(menu);
						reg = true;
						break;
					}
					System.out.println("Client with name " + clientName + " already exists.");
				}
				
				// TODO: need some way to escape back to main menu
				// TODO: should have some way to escape back to main menu?
				while(reg){
        	System.out.print("\n>>");
        	String s = scan.nextLine();
					
					// unregsiter client
	        if(s.equals("u"))
	        {
						if(server.unregisterClient(clientName)){
							System.out.println("You have successfully been unregistered.");
							reg = false;
							break;
						}
						
						// note: this case *shouldn't* happen
						else{
							System.out.println("Error: you are not registered");
						}
	        }
	        
	        // show list of registered clients
	        else if(s.equals("c"))
	        {
						System.out.println(server.getClients());
					}
					
					// send message to client
	        else if(s.equals("m"))
	        {
	        	String encr = "";
	        		        	
	        	System.out.print("To: ");
	        	String to = scan.nextLine();
	        	System.out.print("Message: ");
	        	String msg = scan.nextLine();
	        	
	        	while(!encr.equals("y") && !encr.equals("n")){
	        		System.out.print("Would you like to encrypt this message (y/n)? ");
	        		encr = scan.nextLine();
	        	}
	        	
	        	if(encr.equals("y"))
	        	{
	        		myClient.sendEncryptedMessage(to, msg, "");
	        	}
	        	
	        	else{
	        		myClient.sendMessage(to, msg, "");
	        	}
					}
					
					// listen to a client's communications
	        else if(s.equals("e"))
	        {
	        	System.out.print("Eavesdrop on: ");
	        	String vic = scan.nextLine();
	        	myClient.eavesdrop(vic);
					}

					// stop listening to a client's communications
	        else if(s.equals("s"))
	        {
	        	System.out.print("Stop eavesdropping on: ");
	        	String vic = scan.nextLine();
	        	myClient.stopEavesdrop(vic);
					}
					
					// see list of all received messages
	        else if(s.equals("r"))
	        {
						Map<ClientPair, List<CryptoMessage>> messageMap = myClient.getMessages();
						
						if(!messageMap.isEmpty()){
						
		        	for(Map.Entry<ClientPair, List<CryptoMessage>> entry : messageMap.entrySet()) {
		        		// print "From: ..., To: ..."
		        		ClientPair myPair = entry.getKey();
			        	System.out.println("\n" + myPair +"\n=================");
			        	List<CryptoMessage> messageList = entry.getValue();
			        		
			        	for (CryptoMessage m : messageList) {
			        		// always output encrypted version
			        		System.out.println("Encrypted: " + m.getCipherText());
			        			
			        		// output decrypted version only if myClient was intended target
			        		if(myPair.getTo().equals(myClient.getName())){
			        			System.out.println("Decrypted: " + m.getPlainText());
			        		}
			        	}
		        	}
		        }
		        else{
		        	System.out.println("You have not received or eavesdropped on any messages.");
		        }
					}

					// print help menu
					else if(s.equals("h")){
						System.out.println(menu);
					}					

					else{
						System.out.println("Unrecognized command.");
					}
				}
			}
			

			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}			
	}
}
