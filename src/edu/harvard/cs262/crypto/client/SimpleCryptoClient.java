package edu.harvard.cs262.crypto.client;

import java.rmi.RemoteException;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import edu.harvard.cs262.crypto.CryptoMessage;
import edu.harvard.cs262.crypto.EVote;
import edu.harvard.cs262.crypto.Helpers;
import edu.harvard.cs262.crypto.VPrint;
import edu.harvard.cs262.crypto.cipher.CryptoCipher;
import edu.harvard.cs262.crypto.cipher.KeyExchangeProtocol;
import edu.harvard.cs262.crypto.exception.ClientNotFound;
import edu.harvard.cs262.crypto.exception.EVoteInvalidResult;
import edu.harvard.cs262.crypto.server.CryptoServer;
/**
 * A basic client that deals with sending/receiving non-encrypted messages only
 * 
 */
public class SimpleCryptoClient implements CryptoClient {
	protected final static int VERBOSITY = VPrint.WARN;
	
	protected String name;
	protected CryptoServer server;
	protected VPrint log;
	
	protected Map<ClientPair, List<CryptoMessage>> messages;
	
	public SimpleCryptoClient(String name, CryptoServer server) {
		this.name = name;
		this.server = server;
		
		String logName = String.format("%s %s.log", name, Helpers.currentTimeForFile());
		log = new VPrint(VERBOSITY, logName);
	
		this.messages = new ConcurrentHashMap<ClientPair, List<CryptoMessage>>();
	}


	public String getName() {
		return name;
	}

	public Map<ClientPair, List<CryptoMessage>> getMessages() {
		return this.messages;
	}
	
	
	/**
	 * Expose log so other modules can log actions 
	 */
	public VPrint getLog() {
		return log;
	}

	/**
	 * To detect whether the client has failed
	 */
	public boolean ping() {
		log.print(VPrint.DEBUG2, "pinged");
		return true;
	}
	
	/**
	 * Adds a message being sent to the message list (which is the message history)
	 * @param from
	 * 		Who is sending the message
	 * @param to
	 * 		Who the message is for
	 * @param m
	 * 		The message (can only be non-encrypted for this simple client)
	 */
	protected void recordMessage(String from, String to, CryptoMessage m) {
		ClientPair myPair = new ClientPair(from, to);
		if (messages.containsKey(myPair)) {
			List<CryptoMessage> messageList = messages.get(myPair);
			messageList.add(m);
		} else {
			List<CryptoMessage> messageList = new LinkedList<CryptoMessage>();
			messageList.add(m);
			messages.put(myPair, messageList);
		}
	}

	/**
	 * As the client "to", receive a message sent from client "from"
	 * @param from
	 * 		Who is sending the message
	 * @param to
	 * 		Who the message is for
	 * @param m
	 * 		The message (can only be non-encrypted for this simple client)
	 * @return The message that is received
	 * @throws InterruptedException
	 */
	public String recvMessage(String from, String to, CryptoMessage m) throws InterruptedException {
		log.print(VPrint.DEBUG2, "(%s) recvMessage(%s, %s, m)", name, from, to);
		
		/** Add message to message history */
		recordMessage(from, to, m);
		
		/** Process message (we can't deal with encrypted messages) */
		String plaintext = !m.isEncrypted() ? m.getPlainText() : m.getCipherText();
		log.print(VPrint.QUIET, "%s-%s: %s", from, to, plaintext);
		
		return plaintext;
	}
	
	/**
	 * As the client "from", send an unencrypted message to client "to" by telling the server to do it
	 * @param from
	 * 		Who is sending the message
	 * @param to
	 * 		Who the message is for
	 * @param sid
	 * 		The session id of this communication
	 * @return An empty string
	 * @throws RemoteException, InterruptedException
	 */
	public String sendMessage(String to, String text, String sid) throws RemoteException, InterruptedException {
		if (name.equals(to)) {
			log.print(VPrint.ERROR, "cannot send messages to yourself");
			return "";
		}
		try {
			log.print(VPrint.DEBUG, "(%s) sending message to %s with session %s: %s", name, to, sid, text);
			CryptoMessage m = new CryptoMessage(text, sid);
			if (sid.length() > 0) {
				m.setSessionID(sid);
			}
			return server.sendMessage(name, to, m);
		} catch (ClientNotFound e) {
			log.print(VPrint.ERROR, e.getMessage());
		}
		
		return "";
	}
	
	/**
	 * As the client "from", send an encrypted message to client "to" by telling the server to do it
	 * Note: This simple client actually cannot handle encrypted messages, so it will just say so in the log
	 * @param from
	 * 		Who is sending the message
	 * @param to
	 * 		Who the message is for
	 * @param sid
	 * 		The session id of this communication
	 * @return An empty string
	 * @throws RemoteException, ClientNotFound, InterruptedException
	 */
	public String sendEncryptedMessage(String to, String text, String sid) throws RemoteException,
			ClientNotFound, InterruptedException {
		log.print(VPrint.ERROR, "simple client does not support sending encrypted message");
		return "";
	}	
	
	/**
	 * Waits for a message from a certain session ID
	 * Note: This simple client actually cannot handle waiting, so it will just say so in the log
	 * @param sid
	 * 		The session id of the awaited communication
	 * @return The message that you waited for
	 * @throws RemoteException, InterruptedException
	 */
	public CryptoMessage waitForMessage(String sid) throws RemoteException, InterruptedException {
		log.print(VPrint.ERROR, "simple client does not support waiting for messages");
		return null;
	}	
	
	/**
	 * Eavesdrop on another client
	 * @param victim
	 * 		The person that you want to eavesdrop on
	 * @throws RemoteException
	 */
	public void eavesdrop(String victim) throws RemoteException {
		if (name.equals(victim)) {
			log.print(VPrint.ERROR, "cannot eavesdrop on yourself");
			return;
		}
		try {
			server.eavesdrop(name, victim);
		} catch (ClientNotFound e) {
			log.print(VPrint.ERROR, e.getMessage());
		}
	}

	/**
	 * Stop eavesdropping on a client
	 * @param victim
	 * 		The person that you want to stop eavesdropping on
	 * @throws RemoteException
	 */
	public void stopEavesdrop(String victim) throws RemoteException {
		try {
			server.stopEavesdrop(name, victim);
		} catch (ClientNotFound e) {
			log.print(VPrint.ERROR, e.getMessage());
		}
	}

	/**
	 * Start a secure channel for setting up a shared secret key
	 * Note: This simple client actually cannot handle setting up keys, so it will just say so in the log
	 * @param recip
	 * 		The person you want to set the key up with
	 * @param kx
	 * 		The key exchange protocol being used
	 * @param cipher
	 * 		The cipher being used
	 * @return true if initialization is successful, otherwise false
	 * @throws RemoteException, ClientNotFound, InterruptedException
	 */
	public boolean initSecureChannel(String recip, KeyExchangeProtocol kx, CryptoCipher cipher)
			throws RemoteException, ClientNotFound, InterruptedException {
		log.print(VPrint.ERROR, "simple client does not support secure channels");
		return false;
	}

	/**
	 * Receive the request for setting up a shared secret key through a secure channel
	 * Note: This simple client actually cannot handle setting up keys, so it will just say so in the log
	 * @param counterparty
	 * 		The person trying to set up the key with you
	 * @param kx
	 * 		The key exchange protocol being used
	 * @param cipher
	 * 		The cipher being used
	 * @throws RemoteException, ClientNotFound, InterruptedException
	 */
	public void recvSecureChannel(String counterParty, KeyExchangeProtocol kx, CryptoCipher cipher)
			throws RemoteException, InterruptedException, ClientNotFound {
		log.print(VPrint.ERROR, "simple client does not support secure channels");
		return;
	}

	/**
	 * Aborts an evote
	 * Note: This simple client actually cannot handle evoting, so it will just say so in the log
	 * @param reason
	 * 		The reason that the evote needs to be aborted
	 * @throws RemoteException
	 */
	public void evoteAbort(String reason) throws RemoteException {
		log.print(VPrint.ERROR, "client does not support evoting");
	}

	/**
	 * Participates in an evote
	 * Note: This simple client actually cannot handle evoting, so it will just say so in the log
	 * @param evote
	 * 		The evote to participate in
	 * @throws RemoteException, ClientNotFound, InterruptedException, EVoteInvalidResult
	 */
	public void evote(EVote evote) throws RemoteException, ClientNotFound, InterruptedException, EVoteInvalidResult {
		log.print(VPrint.ERROR, "simple client does not support evoting");
		return;
	}
}
