package edu.harvard.cs262.crypto.client;

import java.util.Map;
import java.util.List;
import java.rmi.Remote;
import java.rmi.RemoteException;

import edu.harvard.cs262.crypto.CryptoMessage;
import edu.harvard.cs262.crypto.EVote;
import edu.harvard.cs262.crypto.VPrint;
import edu.harvard.cs262.crypto.cipher.CryptoCipher;
import edu.harvard.cs262.crypto.cipher.KeyExchangeProtocol;
import edu.harvard.cs262.crypto.exception.ClientNotFound;
import edu.harvard.cs262.crypto.exception.EVoteInvalidResult;
/**
 * Interface for implementing a client that sends/receives encrypted messages.
 * All methods need to throw RemoteException in order for interface to be remote.
 * Interface needs to be remote so a stub can be generated.
 */

public interface CryptoClient extends Remote {
	public String getName() throws RemoteException;
	public Map<ClientPair, List<CryptoMessage>> getMessages() throws RemoteException;
	public VPrint getLog() throws RemoteException;
	public boolean ping() throws RemoteException;
	
	/**
	 * Handlers for client to send/receive messages.
	 */
	String recvMessage(String from, String to, CryptoMessage m) throws RemoteException, InterruptedException;
	String sendMessage(String to, String msg, String sid) throws RemoteException, ClientNotFound, InterruptedException;
	String sendEncryptedMessage(String to, String text, String sid) throws RemoteException, ClientNotFound, InterruptedException;
	CryptoMessage waitForMessage(String sid) throws RemoteException, InterruptedException;
	
	/**
	 * Handlers for client to eavesdrop and stop eavesdropping on other clients
	 */
	void eavesdrop(String victim) throws RemoteException, ClientNotFound;
	void stopEavesdrop(String victim) throws RemoteException, ClientNotFound;
	
	/**
	 * Handlers for client to set up key exchange protocol with another client
	 */
	public boolean initSecureChannel(String recip, KeyExchangeProtocol kx, CryptoCipher cipher) throws RemoteException, ClientNotFound, InterruptedException;
	public void recvSecureChannel(String counterParty, KeyExchangeProtocol kx, CryptoCipher cipher) throws RemoteException, InterruptedException, ClientNotFound;
	
	/**
	 * Handlers for client to abort an e-vote if one if the other clients fail
	 */
	void evoteAbort(String reason) throws RemoteException;
	public void evote(EVote evote) throws RemoteException, ClientNotFound, InterruptedException, EVoteInvalidResult;
}
