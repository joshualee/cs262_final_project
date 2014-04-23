package edu.harvard.cs262.crypto;

import java.math.BigInteger;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.Map;
import java.util.Random;
import java.util.Scanner;
import java.util.concurrent.ConcurrentHashMap;

public class DHCryptoClient implements CryptoClient {
	private final int VERBOSE;
	private String name;
	private CryptoServer server;
	private Map<String, CryptoCipher> ciphers;
	private Map<String, CryptoMessage> sessions;
	
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
	}

	@Override
	public void receiveMessage(String from, CryptoMessage m) throws InterruptedException {
		String plaintext;
		
		if (m.hasSessionID()) {
			String sid = m.getSessionID();
			/*
			 * If there is already a waiting message, wait for
			 * message to be processed before adding to queue.
			 */
			while (sessions.containsKey(sid)) {
				verbosePrint("Warning: session " + sid + " already has a waiting message", 1);
				sessions.wait();
			}
			sessions.put(sid, m);
			
			return;
		}
		
		if (m.isEncrypted()) {
			CryptoCipher key = ciphers.get(from);
			plaintext = key.decrypt(m);
			
			assert(plaintext.equals(m.getPlainText()));
			verbosePrint(from + " (ciphertext): " + m.getCipherText(), 0);
		}
		else {
			plaintext = m.getPlainText();
		}
		
		verbosePrint(from + ": " + plaintext, 0);
	}
	
	
	public CryptoMessage waitForMessage(String sid) throws InterruptedException {
		
		while (!sessions.containsKey(sid)) {
			sessions.wait();
		}
		CryptoMessage m = sessions.remove(sid);
		sessions.notifyAll();
		
		return m;
	}
	
	public void recvSecureChannel(String counterParty, KeyExchangeProtocol kx, CryptoCipher cipher) throws RemoteException, InterruptedException, ClientNotFound {
		if (ciphers.containsKey(counterParty)) {
			verbosePrint("Warning: key for " + counterParty + " already exists", 1);
		}
		
		CryptoKey key = kx.reciprocate(this, counterParty);
		cipher.setKey(key);
		ciphers.put(counterParty, cipher);
	}
	
	public void initSecureChannel(String counterParty, KeyExchangeProtocol kx, CryptoCipher cipher) throws RemoteException, ClientNotFound, InterruptedException {
		if (ciphers.containsKey(counterParty)) {
			verbosePrint("Warning: key for " + counterParty + " already exists", 1);
		}
		
		// indirectly invoke the counterpart of the key exchange on remote client
		server.relaySecureChannel(name, counterParty, kx, cipher);
		CryptoKey key = kx.initiate(this, counterParty);
		cipher.setKey(key);
		ciphers.put(counterParty, cipher);
	}

	@Override
	public boolean ping() {
		return true;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public void sendMessage(String to, String text, String sid) throws RemoteException, ClientNotFound, InterruptedException {
		CryptoMessage m = new CryptoMessage(text, sid);
		if (sid.length() > 0) {
			m.setSessionID(sid);	
		}
		
		server.sendMessage(name, to, m);
	}
	
	public void sendEncryptedMessage(String to, String text, String sid) throws RemoteException, ClientNotFound, InterruptedException {
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
	}
	
	public static void main(String args[]) {
		
		if (args.length != 4) {
			System.err.println("usage: java DHCryptoClient rmiHost rmiPort serverName clientName");
			System.exit(1);
		}
		
		String rmiHost = args[0];
		int rmiPort = Integer.parseInt(args[1]);
		String serverName = args[2];
		String clientName = args[3];
		
		if (System.getSecurityManager() == null) {
			System.setSecurityManager(new SecurityManager());
		}
		
		try {
			Registry registry = LocateRegistry.getRegistry(rmiHost, rmiPort);
			CryptoServer server = (CryptoServer) registry.lookup(serverName);
			CryptoClient myClient = new DHCryptoClient(clientName, server);
			
			Scanner scan = new Scanner(System.in);
			
			while (true) {
				System.out.print("To: ");
				String to = scan.next();
				System.out.print("Message: ");
				String msg = scan.next();
				
				myClient.sendMessage(to, msg, "");
			}
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}		
	  	// args[0]: IP (registry)
		// args[1]: Server name
		// args[2]: Port (registry)
		// args[3]: name
		
	}
	
	/*
	public void doEVote(EVote evote) {
		System.out.println("Initiating e-vote:");
		System.out.print("Ballot: ");
		System.out.println(evote.ballot);
		
		String sid = evote.id.toString();
		
		Random rand = new Random();
		
		int sk = rand.nextInt(evote.p.intValue());
		
		// TODO: vote input instead of random
		int yay_or_nay = rand.nextInt(2);
		int vote = MathHelpers.ipow(evote.g.intValue(), yay_or_nay);
		
		server.recvMessage(Integer.toString(sk));
		CryptoMessage pkMessage = waitForMessage(sid);
		
		// since for now we only do the encryption phase,
		// we only have to set the public key
		ElGamalCipher EGCipher = new ElGamalCipher();
		DHTuple	dht = new DHTuple(evote.p.intValue(), evote.g.intValue(), 
				Integer.parseInt(pkMessage.getPlainText()));
		
		CryptoKey publicKey = new CryptoKey(null, dht);
		EGCipher.setKey(publicKey);
		
		CryptoMessage encryptedVote = EGCipher.encrypt(Integer.toString(vote));
		
		
		// send tag with server message, so clients know what they are seeing when eaves dropping
		server.recvMessage(encryptedVote);
		
		CryptoMessage encryptedResult = waitForMessage(sid);
		
		int c1 = (Integer) encryptedResult.getEncryptionState();
		int c2 = Integer.parseInt(encryptedResult.getPlainText());
		int encC1 = MathHelpers.ipow(c1, sk);
		
		CryptoMessage combinedCipher = waitForMessage(sid);
//		int egPrivateKey = combinedCipher;  
		
		// TODO: no clean way to pass in this to ElGamal since it isn't really the private key
		// but rather what you take the inverse of and multiply directly...
		CryptoKey fullKey = new CryptoKey(null, dht);
	}
	
	*/
}
