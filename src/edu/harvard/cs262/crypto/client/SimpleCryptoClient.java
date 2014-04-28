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

public class SimpleCryptoClient implements CryptoClient {
	protected final static int VERBOSITY = VPrint.DEBUG;
	
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
	
	
	/**
	 * Expose log so other modules can log actions 
	 */
	public VPrint getLog() {
		return log;
	}
	
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

	@Override
	public void recvMessage(String from, String to, CryptoMessage m) throws InterruptedException {
		log.print(VPrint.DEBUG2, "(%s) recvMessage(%s, %s, m)", name, from, to);
		
		// add message to message history
		recordMessage(from, to, m);
		
		// process message (we can't deal with encrypted messages)
		String plaintext = !m.isEncrypted() ? m.getPlainText() : m.getCipherText();
		log.print(VPrint.QUIET, "%s-%s: %s", from, to, plaintext);
	}
	

	@Override
	public boolean ping() {
		log.print(VPrint.DEBUG2, "pinged");
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
	

	@Override
	public void sendMessage(String to, String text, String sid) throws RemoteException, InterruptedException {
		try {
			log.print(VPrint.DEBUG, "(%s) sending message to %s with session %s: %s", name, to, sid, text);
			CryptoMessage m = new CryptoMessage(text, sid);
			if (sid.length() > 0) {
				m.setSessionID(sid);
			}
			server.sendMessage(name, to, m);
		} catch (ClientNotFound e) {
			log.print(VPrint.ERROR, e.getMessage());
		}
	}
	
	@Override
	public void eavesdrop(String victim) throws RemoteException {
		try {
			server.eavesdrop(name, victim);
		} catch (ClientNotFound e) {
			log.print(VPrint.ERROR, e.getMessage());
		}
	}

	@Override
	public void stopEavesdrop(String victim) throws RemoteException {
		try {
			server.stopEavesdrop(name, victim);
		} catch (ClientNotFound e) {
			log.print(VPrint.ERROR, e.getMessage());
		}
	}


	@Override
	public void sendEncryptedMessage(String to, String text, String sid) throws RemoteException,
			ClientNotFound, InterruptedException {
		log.print(VPrint.ERROR, "simple client does not support sending encrypted message");
	}


	@Override
	public CryptoMessage waitForMessage(String sid) throws RemoteException, InterruptedException {
		log.print(VPrint.ERROR, "simple client does not support waiting for messages");
		return null;
	}


	@Override
	public boolean initSecureChannel(String recip, KeyExchangeProtocol kx, CryptoCipher cipher)
			throws RemoteException, ClientNotFound, InterruptedException {
		log.print(VPrint.ERROR, "simple client does not support secure channels");
		return false;
	}


	@Override
	public void recvSecureChannel(String counterParty, KeyExchangeProtocol kx, CryptoCipher cipher)
			throws RemoteException, InterruptedException, ClientNotFound {
		log.print(VPrint.ERROR, "simple client does not support secure channels");
		return;
	}


	@Override
	public void evote(EVote evote) throws RemoteException, ClientNotFound, InterruptedException, EVoteInvalidResult {
		log.print(VPrint.ERROR, "simple client does not support evoting");
		return;
	}

}
