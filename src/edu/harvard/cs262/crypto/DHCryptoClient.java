/**
 * A CryptoClient that uses DiffieHellman key exchange and ElGamal encryption.
 * This client also supports evoting.  
 */

package edu.harvard.cs262.crypto;

import java.math.BigInteger;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.sql.Timestamp;
import java.util.Date;
import java.util.List;
import java.util.LinkedList;
import java.util.Map;
import java.util.Random;
import java.util.Scanner;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class DHCryptoClient implements CryptoClient {
	private final static int VERBOSITY = VPrint.WARN;
	
	private String name;
	private CryptoServer server;
	private VPrint log;
	
	private Map<String, CryptoCipher> ciphers;
	private Map<String, CryptoMessage> sessions;
	private Map<ClientPair, List<CryptoMessage>> messages;
	
	public DHCryptoClient(String name, CryptoServer server) {
		this.name = name;
		this.server = server;
		
		String logName = String.format("%s %s.log", name, Helpers.currentTimeForFile());
		log = new VPrint(VERBOSITY, logName);
		
		this.ciphers = new ConcurrentHashMap<String, CryptoCipher>();
		this.sessions = new ConcurrentHashMap<String, CryptoMessage>();
		this.messages = new ConcurrentHashMap<ClientPair, List<CryptoMessage>>();
	}
	
	/**
	 * Expose log so other modules can log actions 
	 */
	public VPrint getLog() {
		return log;
	}

	@SuppressWarnings("static-access")
	@Override
	public void recvMessage(String from, String to, CryptoMessage m) throws InterruptedException {
		log.print(log.DEBUG2, "(%s) recvMessage(%s, %s, m)", name, from, to);
		
		String plaintext;
		
		/*
		 * Add message to message history
		 */
		ClientPair myPair = new ClientPair(from, to);
		if (messages.containsKey(myPair)) {
			List<CryptoMessage> messageList = messages.get(myPair);
			messageList.add(m);
		} else {
			List<CryptoMessage> messageList = new LinkedList<CryptoMessage>();
			messageList.add(m);
			messages.put(myPair, messageList);
		}
		
		/*
		 * Add message to session queue if it has a session id in order to
		 * pass the message to the appropriate waiting thread.
		 */
		if (m.hasSessionID() && to.equals(name)) {
			String sid = m.getSessionID();
			log.print(log.DEBUG, "(%s) got message with sid %s", name, sid);
			/*
			 * If there is already a waiting message, wait for message to be
			 * processed before adding to queue.
			 */
			synchronized (sessions) {
				while (sessions.containsKey(sid)) {
					log.print(log.WARN,
							"session %s already has a waiting message", sid);
					sessions.wait();
				}
				sessions.put(sid, m);
				sessions.notifyAll();
			}
			log.print(log.DEBUG2, "(%s) done recvMessage", name);
			return;
		}
		
		/*
		 * Process message
		 */
		if (!m.isEncrypted()) {
			plaintext = m.getPlainText();
		}
		else {
			CryptoCipher key = ciphers.get(from);
			if (key != null) {
				plaintext = key.decrypt(m);
				
				if (!plaintext.equals(m.getPlainText())) {
					log.print(log.WARN, "decryption '%s' does not match original plaintext '%s'", plaintext, m.getPlainText());
				}
				log.print(log.LOUD, "%s-%s (ciphertext): %s", from, to, m.getCipherText());
			}
			else {
				plaintext = m.getCipherText();
			}
		}
		log.print(log.QUIET, "%s-%s: %s", from, to, plaintext);
	}
	
	@SuppressWarnings("static-access")
	public CryptoMessage waitForMessage(String sid) throws RemoteException, InterruptedException {
		CryptoMessage m;
		synchronized(sessions) {
			while (!sessions.containsKey(sid)) {
				log.print(log.DEBUG, "(%s) waiting for session '%s'", name, sid);
				sessions.wait();
			}
			log.print(log.DEBUG, "(%s) got message for session '%s'", name, sid);
			m = sessions.remove(sid);
			sessions.notifyAll();
		}
		
		return m;
	}
	
	@SuppressWarnings("static-access")
	public void recvSecureChannel(String counterParty, KeyExchangeProtocol kx, CryptoCipher cipher) throws RemoteException, InterruptedException, ClientNotFound {
		try {
			if (ciphers.containsKey(counterParty)) {
				log.print(log.WARN, "encryption key for %s already exists", counterParty);
			}

			CryptoKey key = kx.reciprocate(this, counterParty);
			cipher.setKey(key);
			ciphers.put(counterParty, cipher);
		} catch (ClientNotFound e) {
			log.print(log.ERROR, e.getMessage());
		}
	}
	
	private class initSecureChannelCallable implements Callable<CryptoKey> {
		private String counterParty;
		private KeyExchangeProtocol kx;
		private CryptoClient client;
		
		public initSecureChannelCallable(String cp, KeyExchangeProtocol kx, CryptoClient client) {
			this.counterParty = cp;
			this.kx = kx;
			this.client = client;
		}
		
		@Override
		public CryptoKey call() throws Exception {
			CryptoKey key = kx.initiate(client, counterParty);
			return key;
		}
	}
	
	private class recvSecureChannelCallable implements Callable<Object> {
		private String counterParty;
		private KeyExchangeProtocol kx;
		private CryptoCipher cipher;
		
		public recvSecureChannelCallable(String cp, KeyExchangeProtocol kx, CryptoCipher cipher) {
			this.counterParty = cp;
			this.kx = kx;
			this.cipher = cipher;
		}
		
		@Override
		public Object call() throws Exception {
			server.relaySecureChannel(name, counterParty, kx, cipher);
			// the result of this call is stored in the counterParty
			// thus we don't care about the return result, only the exceptions that may be thrown
			return null;
		}
	}
	
	@SuppressWarnings("static-access")
	public boolean initSecureChannel(String counterParty, KeyExchangeProtocol kx, CryptoCipher cipher) throws RemoteException, ClientNotFound, InterruptedException {
		CryptoKey key = null;
		Future<CryptoKey> myFuture = null;
		Future<Object> cpFuture;
		
		log.print(log.DEBUG2, "%s: initSecureChannel", name);

		if (ciphers.containsKey(counterParty)) {
			log.print(log.WARN, "encryption key for %s already exists", counterParty);
		}
		
		ExecutorService pool = Executors.newFixedThreadPool(2);
		myFuture = pool.submit(new initSecureChannelCallable(counterParty, kx, this));
		cpFuture = pool.submit(new recvSecureChannelCallable(counterParty, kx, cipher));
		
		while (!cpFuture.isDone()) {
			// myFuture doesn't finish until cpFuture finishes 
		}
		
		/*
		 * Check if counter party succeeded or threw an error
		 * (e.g. ClientNotFound)
		 */
		try {
			cpFuture.get();
		}
		catch (ExecutionException e) {
			// TODO: we should cancel the other thread here, but
			// this closes the log file and causes IO exceptions...
			// myFuture.cancel(true);
			log.print(log.ERROR, e.getCause().getMessage());
			return false;
		}
		
		/*
		 * Make sure we succeeded
		 */
		try {
			key = myFuture.get();
		} catch (ExecutionException e) {
			log.print(log.ERROR, e.getCause().getMessage());
			return false;
		} catch (CancellationException e) {
			log.print(log.ERROR, "%s failed to reciprocate key exchange", counterParty);
			return false;
		}
		
		cipher.setKey(key);
		ciphers.put(counterParty, cipher);
		return true;
	}

	@SuppressWarnings("static-access")
	@Override
	public boolean ping() {
		log.print(log.DEBUG2, "pinged");
		return true;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public Map<ClientPair, List<CryptoMessage>> getMessages() {
		return this.messages;
	}

	@SuppressWarnings("static-access")
	@Override
	public void sendMessage(String to, String text, String sid) throws RemoteException, InterruptedException {
		try {
			log.print(log.DEBUG, "(%s) sending message to %s with session %s: %s", name, to, sid, text);
			CryptoMessage m = new CryptoMessage(text, sid);
			if (sid.length() > 0) {
				m.setSessionID(sid);
			}
			server.sendMessage(name, to, m);
		} catch (ClientNotFound e) {
			log.print(log.ERROR, e.getMessage());
		}
	}
	
	// To do: hangs if Client 'to' is unregistered
	@SuppressWarnings("static-access")
	public void sendEncryptedMessage(String to, String text, String sid) throws RemoteException, InterruptedException {
		if (name.equals(to)) {
			log.print(VPrint.ERROR, "cannot send encrypted messages to yourself");
			return;
		}
		
		try {
			CryptoCipher c = ciphers.get(to);
			if (c == null) {
				DiffieHellman dh = new DiffieHellman();
				ElGamalCipher eg = new ElGamalCipher();
				if (initSecureChannel(to, dh, eg)) {
					sendEncryptedMessage(to, text, sid);	
				}
				return;
			}

			CryptoMessage m = c.encrypt(text);
			m.setSessionID(sid);
			server.sendMessage(name, to, m);
		} catch (ClientNotFound e) {
			log.print(log.ERROR, e.getMessage());
		}
	}
	

	@SuppressWarnings("static-access")
	@Override
	public void eavesdrop(String victim) throws RemoteException {
		try {
			server.eavesdrop(name, victim);
		} catch (ClientNotFound e) {
			log.print(log.ERROR, e.getMessage());
		}
	}

	@SuppressWarnings("static-access")
	@Override
	public void stopEavesdrop(String victim) throws RemoteException {
		try {
			server.stopEavesdrop(name, victim);
		} catch (ClientNotFound e) {
			log.print(log.ERROR, e.getMessage());
		}
	}

	// does this need to throw ClientNotFound?	
	public void eVote(EVote evote) throws RemoteException, ClientNotFound, InterruptedException {
		Random rand = new Random(262);
		String sid = evote.id.toString();
		
		/*
		 * EVote phase one: 
		 * client receives a ballot from the server
		 */
		log.print(VPrint.QUIET, "initiating e-vote...");
		log.print(VPrint.QUIET, "ballot %s: %s", sid, evote.ballot);
		
		//int yay_or_nay = rand.nextInt(2);
		
		int yay_or_nay;
		String clientVote = "";
		
		log.print(VPrint.QUIET, "y: vote in favor");
		log.print(VPrint.QUIET, "n: vote against");
		log.print(VPrint.QUIET, "vote [y\\n]: ");
		
		Scanner scan = new Scanner(System.in);
		
		while (true) {
			clientVote = scan.nextLine();
			if (clientVote.equals("y")) {
				log.print(VPrint.LOUD, "you voted in favor ballot %s", sid);
				yay_or_nay = 1;
				break;
			}
			else if (clientVote.equals("n")) {
				log.print(VPrint.LOUD, "you voted in against ballot %s", sid);
				yay_or_nay = 0;
				break;
			}
			else {
				log.print(VPrint.QUIET, "try again [y\\n]: ");
			}
		}
		
		scan.close();
		
		log.print(VPrint.QUIET, "tallying vote...");
		
		
		/*
		 * EVote phase two: 
		 * each client generates own secret key and sends to server
		 */
		BigInteger sk_i = (new BigInteger(evote.BITS, rand)).mod(evote.p);
		BigInteger pk_i = evote.g.modPow(sk_i, evote.p);
		
		
		log.print(VPrint.DEBUG, "g=%s, p=%s", evote.g, evote.p);
		log.print(VPrint.DEBUG, "sk_i=%s, pk_i=%s", sk_i, pk_i);
		
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
		CryptoMessage encryptedVote = EGCipher.encryptInteger(vote);
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
		int numYays, numNays;
		int numVoters = evote.voters.size();
		
		CryptoMessage decodingKeyMsg = waitForMessage(sid);
		BigInteger decodingKey = new BigInteger(decodingKeyMsg.getPlainText());
		BigInteger voteResult = c2.multiply(decodingKey.modInverse(evote.p)).mod(evote.p);
		
		try {
			numYays = evote.countYays(voteResult, numVoters);
			numNays = numVoters - numYays;
		} catch (EVoteInvalidResult e) {
			log.print(VPrint.ERROR, "evote failed: %s", e.getMessage());
			return;
		}
		
		log.print(VPrint.DEBUG, "raw vote result: %s", voteResult.toString());
		
		log.print(VPrint.QUIET, "ballot %s vote results: %d voted yes, %d voted no", sid, numYays, numNays);

		if (numYays > numNays) {
			log.print(VPrint.QUIET, "ballot %s has passed");
		}
		else {
			log.print(VPrint.QUIET, "ballot %s has NOT passed", sid);
		}
	}
	
	public static void main(String args[]) {
		if (args.length < 3) {
			System.err.println("usage: java DHCryptoClient rmiHost rmiPort serverName");
			System.exit(1);
		}

		String rmiHost = args[0];
		int rmiPort = Integer.parseInt(args[1]);
		String serverName = args[2];

		if (System.getSecurityManager() == null) {
			System.setSecurityManager(new SecurityManager());
		}

		try {
			String clientName = "";
			CryptoClient myClient = null;
			Registry registry = LocateRegistry.getRegistry(rmiHost, rmiPort);
			CryptoServer server = (CryptoServer) registry.lookup(serverName);

			// Create new Scanner
			Scanner scan = new Scanner(System.in);

			// boolean to keep track of whether the Client is registered
			boolean reg = false;

			// Menu
			String menu = 
				"\n====== Help Menu ======\n" +
			    "u: unregister\n" +
			    "c: see list of registered clients\n" +
				"m: send message to client\n" +
				"e: listen to a client's communications\n" +
				"s: stop listening to a client's communications\n" +
				"r: see list of all received messages\n" +
				"q: quit\n" +
				"h: display this menu";

			while (true) {

				// make client register before it can do anything else
				while (!reg) {
					System.out.print("Enter your name: ");
					clientName = scan.nextLine();
					
					myClient = new DHCryptoClient(clientName, server);
					CryptoClient myClientSer = ((CryptoClient) UnicastRemoteObject
							.exportObject(myClient, 0));

					if (server.registerClient(myClientSer)) {
						System.out.println(menu);
						reg = true;
						break;
					}
					System.out.println("Client with name " + clientName + " already exists.");
				}

				// TODO: need some way to escape back to main menu
				// TODO: should have some way to escape back to main menu?
				while (reg) {
					System.out.print("\n>> ");
					String s = scan.nextLine();

					// unregsiter client
					if (s.equals("u")) {
						if (server.unregisterClient(clientName)) {
							System.out.println("You have successfully been unregistered.");
							reg = false;
							break;
						}

						// note: this case *shouldn't* happen
						else {
							System.out.println("Error: you are not registered");
						}
					}

					// show list of registered clients
					else if (s.equals("c")) {
						System.out.println(server.getClients());
					}

					// send message to client
					else if (s.equals("m")) {
						String encr = "";

						System.out.print("To: ");
						String to = scan.nextLine();
						System.out.print("Message: ");
						String msg = scan.nextLine();

						while (!encr.equals("y") && !encr.equals("n")) {
							System.out.print("Would you like to encrypt this message (y/n)? ");
							encr = scan.nextLine();
						}

						if (encr.equals("y")) {
							myClient.sendEncryptedMessage(to, msg, "");
						}

						else {
							myClient.sendMessage(to, msg, "");
						}
					}

					// listen to a client's communications
					else if (s.equals("e")) {
						System.out.print("Eavesdrop on: ");
						String vic = scan.nextLine();
						myClient.eavesdrop(vic);
					}

					// stop listening to a client's communications
					else if (s.equals("s")) {
						System.out.print("Stop eavesdropping on: ");
						String vic = scan.nextLine();
						myClient.stopEavesdrop(vic);
					}

					// see list of all received messages
					else if (s.equals("r")) {
						Map<ClientPair, List<CryptoMessage>> messageMap = myClient.getMessages();

						if (!messageMap.isEmpty()) {

							for (Map.Entry<ClientPair, List<CryptoMessage>> entry : messageMap
									.entrySet()) {
								// print "From: ..., To: ..."
								ClientPair myPair = entry.getKey();
								System.out.println("\n" + myPair + "\n=================");
								List<CryptoMessage> messageList = entry.getValue();

								for (CryptoMessage m : messageList) {
									// always output encrypted version
									System.out.println("Encrypted: " + m.getCipherText());

									// output decrypted version only if myClient
									// was intended target
									if (myPair.getTo().equals(myClient.getName())) {
										System.out.println("Decrypted: " + m.getPlainText());
									}
								}
							}
						} else {
							System.out
									.println("You have not received or eavesdropped on any messages.");
						}
					}

					// print help menu
					else if (s.equals("h")) {
						System.out.println(menu);
					}
					else if (s.equals("q")) {
						System.exit(0);
					}
					else {
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
