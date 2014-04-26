package edu.harvard.cs262.crypto;

import java.math.BigInteger;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.util.Map;
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
	public void recvMessage(String from, String to, CryptoMessage m) throws InterruptedException {
		System.out.println(String.format("(%s) recvMessage(%s, %s, m)", name, from, to));
		
		String plaintext;
		
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
		if (ciphers.containsKey(counterParty)) {
			verbosePrint("Warning: key for " + counterParty + " already exists", 1);
		}
		
		CryptoKey key = kx.reciprocate(this, counterParty);
		cipher.setKey(key);
		ciphers.put(counterParty, cipher);
	}
	
	public void initSecureChannel(final String counterParty, final KeyExchangeProtocol kx, final CryptoCipher cipher) throws RemoteException, ClientNotFound, InterruptedException {
		System.out.println(String.format("%s: initSecureChannel", name));
		
		if (ciphers.containsKey(counterParty)) {
			verbosePrint("Warning: key for " + counterParty + " already exists", 1);
		}
		
		// indirectly invoke the counterpart of the key exchange on remote client
		
		Helpers.doAsync(new Runnable() { public void run() {
			try {
				server.relaySecureChannel(name, counterParty, kx, cipher);
			} catch (Exception e) {
				e.printStackTrace();
			}
		} });
		
		System.out.println(String.format("%s: about to kx.initiate", name));
		CryptoKey key = kx.initiate(this, counterParty);
		System.out.println(String.format("%s: finished kx.initiate", name));
		cipher.setKey(key);
		ciphers.put(counterParty, cipher);
	}

	@Override
	public boolean ping() {
		System.out.println("pinged");
		return true;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public void sendMessage(String to, String text, String sid) throws RemoteException, ClientNotFound, InterruptedException {
		System.out.println(String.format("(%s) sending message to %s with session %s: %s", name, to, sid, text));
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
		
		// args[0]: IP (registry)
		// args[1]: Port (registry)
		// args[2]: Server name
		// args[3]: Client name
		
		String rmiHost = args[0];
		int rmiPort = Integer.parseInt(args[1]);
		String serverName = args[2];
		//String clientName = args[3];
		
		if (System.getSecurityManager() == null) {
			System.setSecurityManager(new SecurityManager());
		}
		
		try {
			Registry registry = LocateRegistry.getRegistry(rmiHost, rmiPort);
			CryptoServer server = (CryptoServer) registry.lookup(serverName);
			//CryptoClient myClient = new DHCryptoClient(clientName, server);
			//CryptoClient myClientSer = ((CryptoClient)UnicastRemoteObject.exportObject(myClient, 0));

      //Create new Scanner
      Scanner scan = new Scanner(System.in);
      			
			// boolean to keep track of whether the Client is registered
      boolean reg = false;
			
			while(true){
				
				// make client register before it can do anything else
				while(!reg){
					System.out.print("Enter your name: ");
					String clientName = scan.nextLine();							
					CryptoClient myClient = new DHCryptoClient(clientName, server);
					CryptoClient myClientSer = ((CryptoClient)UnicastRemoteObject.exportObject(myClient, 0));
					if(server.registerClient(myClientSer)){
						reg = true;
						break;
					}
					else{
						System.out.println("Client with name " + clientName + " already exists.");
					}
				}
				
				while(reg){
					System.out.print("hi!");
					String temp = scan.nextLine();
				}

			}
			

			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}			
	}

	@Override
	public void eavesdrop(String victim) throws RemoteException, ClientNotFound {
		server.eavesdrop(name, victim);
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
