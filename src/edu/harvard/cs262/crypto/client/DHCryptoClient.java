package edu.harvard.cs262.crypto.client;

import java.rmi.RemoteException;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import edu.harvard.cs262.crypto.CryptoMessage;
import edu.harvard.cs262.crypto.EVote;
import edu.harvard.cs262.crypto.VPrint;
import edu.harvard.cs262.crypto.cipher.CryptoCipher;
import edu.harvard.cs262.crypto.cipher.CryptoKey;
import edu.harvard.cs262.crypto.cipher.DiffieHellman;
import edu.harvard.cs262.crypto.cipher.ElGamalCipher;
import edu.harvard.cs262.crypto.cipher.KeyExchangeProtocol;
import edu.harvard.cs262.crypto.exception.ClientNotFound;
import edu.harvard.cs262.crypto.exception.EVoteInvalidResult;
import edu.harvard.cs262.crypto.server.CryptoServer;

/**
 * A CryptoClient that uses DiffieHellman key exchange and ElGamal encryption.
 * This client does not support e-voting.  
 *
 * @author Holly Anderson, Joshua Lee, and Tracy Lu
 */

public class DHCryptoClient extends SimpleCryptoClient {	
	protected Map<String, CryptoCipher> ciphers;
	protected Map<String, CryptoMessage> sessions;
	
	public DHCryptoClient(String name, CryptoServer server) {
		super(name, server);
		this.ciphers = new ConcurrentHashMap<String, CryptoCipher>();
		this.sessions = new ConcurrentHashMap<String, CryptoMessage>();
	}
	
	/**
	 * As the client "to", receive a message sent from client "from"
	 * @param from
	 * 		Who is sending the message
	 * @param to
	 * 		Who the message is for
	 * @param m
	 * 		The message
	 * @return The message that is received
	 * @throws InterruptedException
	 */
	public String recvMessage(String from, String to, CryptoMessage m) throws InterruptedException {
		String plaintext;
		
		log.print(VPrint.DEBUG2, "(%s) recvMessage(%s, %s, m)", name, from, to);
		
		/**
		 * Add message to message history
		 */
		recordMessage(from, to, m);
		
		/**
		 * Add message to session queue if it has a session id in order to
		 * pass the message to the appropriate waiting thread.
		 */
		if (m.hasSessionID() && to.equals(name)) {
			String sid = m.getSessionID();
			log.print(VPrint.DEBUG, "(%s) got message with sid %s", name, sid);
			/**
			 * If there is already a waiting message, wait for message to be
			 * processed before adding to queue.
			 */
			synchronized (sessions) {
				while (sessions.containsKey(sid)) {
					log.print(VPrint.WARN,
							"session %s already has a waiting message", sid);
					sessions.wait();
				}
				sessions.put(sid, m);
				sessions.notifyAll();
			}
			log.print(VPrint.DEBUG2, "(%s) done recvMessage", name);
			return "";
		}

		/**
		 * Process message, decrypt if it is encrypted
		 */
		if (!m.isEncrypted()) {
			plaintext = m.getPlainText();
		}
		else {
			CryptoCipher key = ciphers.get(from);
			if (key != null) {
				plaintext = key.decrypt(m);
				
				if (!plaintext.equals(m.getPlainText())) {
					log.print(VPrint.WARN, "decryption '%s' does not match original plaintext '%s'", plaintext, m.getPlainText());
				}
				log.print(VPrint.LOUD, "%s-%s (ciphertext): %s", from, to, m.getCipherText());
			}
			else {
				plaintext = m.getCipherText();
			}
		}
		
		if (m.hasTag() && !to.equals(name)) {
			log.print(VPrint.QUIET, "%s-%s (%s): %s", from, to, m.getTag(), plaintext);
		} else {
			log.print(VPrint.QUIET, "%s-%s: %s", from, to, plaintext);	
		}
		
		return plaintext;
	}
	
	/**
	 * As the client, send an encrypted message to client "to" by telling the server to do it.
	 * @param to
	 * 		Who the message is for
	 * @param text
	 * 		The message
	 * @param sid
	 * 		The session id of this communication
	 * @return An empty string
	 * @throws RemoteException, ClientNotFound, InterruptedException
	 */
	public String sendEncryptedMessage(String to, String text, String sid) throws RemoteException, InterruptedException {
		if (name.equals(to)) {
			log.print(VPrint.ERROR, "cannot send encrypted messages to yourself");
			return "";
		}
		
		try {
			/** 
			 * Get the cipher to be used and send the encrypted message if the clients have a secret key set up.
			 * Otherwise, first set up a key between the two communicating clients.
			 */
			CryptoCipher c = ciphers.get(to);
			if (c == null) {
				DiffieHellman dh = new DiffieHellman();
				ElGamalCipher eg = new ElGamalCipher();
				if (initSecureChannel(to, dh, eg)) {
					return sendEncryptedMessage(to, text, sid);	
				}
				return "";
			}

			CryptoMessage m = c.encrypt(text);
			m.setSessionID(sid);
			return server.sendMessage(name, to, m);
		} catch (ClientNotFound e) {
			log.print(VPrint.ERROR, e.getMessage());
		}
		
		return "";
	}
	
	/**
	 * Waits for a message from a certain session ID
	 * @param sid
	 * 		The session id of the awaited communication
	 * @return The message that you waited for
	 * @throws RemoteException, InterruptedException
	 */
	public CryptoMessage waitForMessage(String sid) throws RemoteException, InterruptedException {
		CryptoMessage m;
		synchronized(sessions) {
			while (!sessions.containsKey(sid)) {
				log.print(VPrint.DEBUG, "(%s) waiting for session '%s'", name, sid);
				sessions.wait();
			}
			log.print(VPrint.DEBUG, "(%s) got message for session '%s'", name, sid);
			m = sessions.remove(sid);
			sessions.notifyAll();
		}
		
		return m;
	}
	
	public void recvSecureChannel(String counterParty, KeyExchangeProtocol kx, CryptoCipher cipher) throws RemoteException, InterruptedException, ClientNotFound {
		try {
			if (ciphers.containsKey(counterParty)) {
				log.print(VPrint.WARN, "encryption key for %s already exists", counterParty);
			}

			CryptoKey key = kx.reciprocate(this, counterParty);
			cipher.setKey(key);
			ciphers.put(counterParty, cipher);
		} catch (ClientNotFound e) {
			log.print(VPrint.ERROR, e.getMessage());
		}
	}
	
	/**
	 * Class for creating callable object for initiating a secure channel for the key exchange protocol
	 */
	private class initSecureChannelCallable implements Callable<CryptoKey> {
		private String counterParty;
		private KeyExchangeProtocol kx;
		private CryptoClient client;
		
		/**
		 * Makes a callable object for initiating a secure channel for the key exchange protocol
		 * @param cp
		 * 		The person you want to set the key up with
		 * @param kx
		 * 		The key exchange protocol being used
		 * @param client
		 * 		The client trying to initialize the key exchange protocol
		 */
		public initSecureChannelCallable(String cp, KeyExchangeProtocol kx, CryptoClient client) {
			this.counterParty = cp;
			this.kx = kx;
			this.client = client;
		}
		
		/**
		 * Initiates the key exchange between two clients
		 * @return the shared secret key
		 */
		public CryptoKey call() throws Exception {
			CryptoKey key = kx.initiate(client, counterParty);
			return key;
		}
	}
	
	/**
	 * Class for creating callable object for receiving a secure channel for the key exchange protocol
	 */
	private class recvSecureChannelCallable implements Callable<Object> {
		private String counterParty;
		private KeyExchangeProtocol kx;
		private CryptoCipher cipher;
		
		/**
		 * Makes callable object for receiving the request for setting up a shared secret key through a secure channel
		 * @param cp
		 * 		The person trying to set up the key with you
		 * @param kx
		 * 		The key exchange protocol being used
		 * @param cipher
		 * 		The cipher being used
		 */
		public recvSecureChannelCallable(String cp, KeyExchangeProtocol kx, CryptoCipher cipher) {
			this.counterParty = cp;
			this.kx = kx;
			this.cipher = cipher;
		}
		
		/**
		 * Receives key exchange initiated by a client
		 */
		public Object call() throws Exception {
			server.relaySecureChannel(name, counterParty, kx, cipher);
			
			/** The result of this call is stored in the counterParty.
			 *  Thus we don't care about the return result, only the exceptions that may be thrown.
			 */
			return null;
		}
	}
	
	/**
	 * Start a secure channel for setting up a shared secret key using different threads to make sure both clients succeed
	 * @param counterParty
	 * 		The person you want to set the key up with
	 * @param kx
	 * 		The key exchange protocol being used
	 * @param cipher
	 * 		The cipher being used
	 * @return true if initialization is successful, otherwise false
	 * @throws RemoteException, ClientNotFound, InterruptedException
	 */
	public boolean initSecureChannel(String counterParty, KeyExchangeProtocol kx, CryptoCipher cipher) throws RemoteException, ClientNotFound, InterruptedException {
		CryptoKey key = null;
		Future<CryptoKey> myFuture = null;
		Future<Object> cpFuture;
		
		log.print(VPrint.DEBUG2, "%s: initSecureChannel", name);

		if (ciphers.containsKey(counterParty)) {
			log.print(VPrint.WARN, "encryption key for %s already exists", counterParty);
		}
		
		KeyExchangeProtocol kx2 = kx.copy();
		CryptoCipher cipher2 = cipher.copy();
		
		/**
		 * In one thread, tell the initiating client to initiate.
		 * In the other thread, tell the receiving client to receive.
		 */
		ExecutorService pool = Executors.newFixedThreadPool(2);
		myFuture = pool.submit(new initSecureChannelCallable(counterParty, kx, this));
		cpFuture = pool.submit(new recvSecureChannelCallable(counterParty, kx2, cipher2));
		
		/** myFuture doesn't finish until cpFuture finishes */
		while (!cpFuture.isDone()) {}
		
		/**
		 * Check if counterparty succeeded or threw an error
		 * (e.g. ClientNotFound)
		 */
		try {
			cpFuture.get();
		}
		catch (ExecutionException e) {
			myFuture.cancel(true);
			log.print(VPrint.ERROR, "key exchange failed because of error with %s", counterParty);
			return false;
		}
		
		/**
		 * Make sure we succeeded
		 */
		try {
			key = myFuture.get();
		} catch (ExecutionException e) {
			log.print(VPrint.ERROR, e.getCause().getMessage());
			return false;
		} catch (CancellationException e) {
			
			log.print(VPrint.ERROR, "%s failed to reciprocate key exchange", counterParty);
			return false;
		}
		
		cipher.setKey(key);
		ciphers.put(counterParty, cipher);
		return true;
	}

	/**
	 * Participates in an evote
	 * Note: This Diffie Helman client actually cannot handle evoting, so it will just say so in the log
	 * @param evote
	 * 		The evote to participate in
	 * @throws RemoteException, ClientNotFound, InterruptedException, EVoteInvalidResult
	 */
	public void evote(EVote evote) throws RemoteException, ClientNotFound, InterruptedException, EVoteInvalidResult {
		log.print(VPrint.ERROR, "diffie hellman client does not support evoting");
		return;
	}
	
	public void dropKeys() {
		ciphers.clear();
	}
	
	public void setKey(String name, CryptoCipher c) {
		ciphers.put(name, c);
	}
}
