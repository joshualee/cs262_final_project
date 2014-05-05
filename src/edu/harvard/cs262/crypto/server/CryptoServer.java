package edu.harvard.cs262.crypto.server;

import java.rmi.Remote;
import java.rmi.RemoteException;

import edu.harvard.cs262.crypto.CryptoMessage;
import edu.harvard.cs262.crypto.cipher.CryptoCipher;
import edu.harvard.cs262.crypto.cipher.KeyExchangeProtocol;
import edu.harvard.cs262.crypto.client.CryptoClient;
import edu.harvard.cs262.crypto.exception.ClientNotFound;

/**
 * Interface for implementing a server that deals with clients sending/receiving encrypted messages
 * and eavesdropping.
 * All methods need to throw RemoteException in order for interface to be remote.
 * Interface needs to be remote so a stub can be generated.
 *
 * @author Holly Anderson, Joshua Lee, and Tracy Lu
 */
public interface CryptoServer extends Remote {
	String getName() throws RemoteException;
	String getClientList(boolean arrayFormat) throws RemoteException;
	
	/**
	 * Return reference to client
	 */
	CryptoClient getClient(String clientName) throws RemoteException, ClientNotFound;
	
	public boolean ping() throws RemoteException;
	
	/**
	 * Register client so server can forward it messages.
	 */
	public boolean registerClient(CryptoClient c) throws RemoteException;
	public boolean unregisterClient(String clientName) throws RemoteException;

	/**
	 * Handle messages sent by clients directed towards server.
	 * CryptoMessage may have session id. Sessions are distinguished
	 * by the tuple (session id, client name)
	 * 
	 * @param from: the name of the client sending the message
	 * @param m: the message from the client
	 * @return The message received
	 * @throws RemoteException
	 * @throws ClientNotFound
	 * @throws InterruptedException 
	 */
	public String recvMessage(String from, String to, CryptoMessage m) throws RemoteException, ClientNotFound, InterruptedException;
	
	/**
	 * Send message "m" from client "from" to client "to".
	 * Blocks until message has successfully been delivered.
	 * @param from: the name of the client sending the message
	 * @param to: the name of the client receiving the message
	 * @param m: the message being sent
	 * @return The message sent
	 * @throws RemoteException
	 * @throws ClientNotFound
	 * @throws InterruptedException 
	 */
	public String sendMessage(String from, String to, CryptoMessage m) throws RemoteException, ClientNotFound, InterruptedException;
	
	/** 
	 * Allow client "listener" to listen to all incoming
	 * and outgoing communication of client "victim"
	 */
	public void eavesdrop(String listener, String victim) throws RemoteException, ClientNotFound;
	
	/** 
	 * Allow client "listener" to stop listening to all incoming
	 * and outgoing communication of client "victim"
	 */
	public void stopEavesdrop(String listener, String victim) throws RemoteException, ClientNotFound;
	
	/**
	 * Starts a secure channel for key exchange setup
	 */
	public void relaySecureChannel(String from, String to, KeyExchangeProtocol kx, CryptoCipher c) throws ClientNotFound, RemoteException, InterruptedException;

	/**
	 * Starts an e-vote
	 */
	public String initiateEVote(String ballot) throws RemoteException, ClientNotFound, InterruptedException;
}
