package edu.harvard.cs262.crypto.server;

import java.rmi.Remote;
import java.rmi.RemoteException;

import edu.harvard.cs262.crypto.CryptoMessage;
import edu.harvard.cs262.crypto.cipher.CryptoCipher;
import edu.harvard.cs262.crypto.cipher.KeyExchangeProtocol;
import edu.harvard.cs262.crypto.client.CryptoClient;
import edu.harvard.cs262.crypto.exception.ClientNotFound;

/**
 * The server interface. Servers are responsible for facilitating client to client interactions
 * such as sending/receiving/eavesdropping encrypted/unencrypted messages. Also more advanced
 * servers also enables applications such as evoting. Servers are responsible for handling
 * faulty clients, such as unresponsive or crashing clients. 
 *
 * @author Holly Anderson, Joshua Lee, and Tracy Lu
 */
public interface CryptoServer extends Remote {
	
	/**
	 * Getter for the name of the server
	 * 
	 * @return the name of the server
	 * @throws RemoteException
	 */
	String getName() throws RemoteException;
	
	/**
	 * Returns the list of currently registered clients.
	 * 
	 * @param arrayFormat
	 * 		indicator of the desired string output format
	 * @return the list of registered clients as a string
	 * @throws RemoteException
	 */
	String getClientList(boolean arrayFormat) throws RemoteException;
	
	/**
	 * Returns a reference to the client with the specified name. This is needed when a client 
	 * wants to communicate with another client directly and not have to go through the server.
	 * This function should be used with care, as it bypasses the server layer, which in general should
	 * not be done.
	 * 
	 * @param clientName
	 * 		the name of the client
	 * @return a reference to the client object
	 * @throws RemoteException, ClientNotFound
	 */
	CryptoClient getClient(String clientName) throws RemoteException, ClientNotFound;
	
	/**
	 * Used to ensure the server is responsive. Only returns true, but may never return if the
	 * server has crashed or just doesn't respond.
	 * 
	 * @return true, meaning the server is alive
	 * @throws RemoteException
	 */
	public boolean ping() throws RemoteException;
	
	/**
	 * Register a remote client so server can forward it messages.
	 * Function is designed to be called by the client.
	 * Clients must first register before using any of the other server functionality.
	 * 
	 * @param c the registering client 
	 * @return true if the client successfully registered
	 */
	public boolean registerClient(CryptoClient c) throws RemoteException;
	
	/**
	 * Unregister a remote client so server can no longer forward it messages.
	 * 
	 * @param c the unregistering client 
	 * @return true if the client successfully unregistered
	 */
	public boolean unregisterClient(String clientName) throws RemoteException;

	/**
	 * Handle messages sent by clients directed towards server.
	 * CryptoMessage "m" may have session id used for synchronization. 
	 * Sessions are distinguished by the tuple (session id, client name)
	 * (so a server may have a separate session with each client)
	 * 
	 * @param from: the name of the client sending the message
	 * @param m: the message from the client
	 * @return the message received
	 * @throws RemoteException, ClientNotFound, InterruptedException 
	 */
	public String recvMessage(String from, String to, CryptoMessage m) throws RemoteException, ClientNotFound, InterruptedException;
	
	/**
	 * Send message "m" from client "from" to client "to".
	 * Blocks until message has successfully been delivered.
	 * Returns the message being sent, so the caller may check
	 * the integrity of the call
	 * 
	 * @param from: the name of the client sending the message
	 * @param to: the name of the client receiving the message
	 * @param m: the message being sent
	 * @return the message sent
	 * @throws RemoteException, ClientNotFound, InterruptedException 
	 */
	public String sendMessage(String from, String to, CryptoMessage m) throws RemoteException, ClientNotFound, InterruptedException;
	
	/**
	 * Allow client "listener" to listen to all incoming and outgoing communication of client 
	 * "victim". Once a client has registered to eavesdrop, the server will automatically forward
	 * all communications to/from "victim" to "listener"
	 * 
	 * @param listener
	 * 		name of client listening
	 * @param victim
	 * 		name of client to listen to
	 * @throws RemoteException, ClientNotFound
	 */
	public void eavesdrop(String listener, String victim) throws RemoteException, ClientNotFound;
	
	/**
	 * Allow client "listener" to stop listening to communications of client "victim"
	 * 
	 * @param listener
	 * 		name of client no longer listening
	 * @param victim
	 * 		name of client to no longer listen to
	 * @throws RemoteException, ClientNotFound
	 */
	public void stopEavesdrop(String listener, String victim) throws RemoteException, ClientNotFound;
	
	/**
	 * Relay a request from client "from" to create a secure channel with client "to" that
	 * uses the KeyExchangeProtocol "kx" and CryptoCipher "c". This is a remote method intended
	 * to be called by the client who wishes to create the secure channel.
	 * 
	 * @param from
	 * 		the name of the client requesting to create the secure channel
	 * @param to
	 * 		the name of the client targeted to create the secure channel with
	 * @param kx
	 * 		the key exchange protocol being used
	 * @param c
	 * 		the crypto cipher being used
	 * @throws ClientNotFound, RemoteException, InterruptedException
	 */
	public void relaySecureChannel(String from, String to, KeyExchangeProtocol kx, CryptoCipher c) throws ClientNotFound, RemoteException, InterruptedException;

	/**
	 * Initiate an evote with all currently registered clients. Handles the coordination of the
	 * evote protocol.
	 * 
	 * @param ballot
	 * 		the item to voted on
	 * @return the result of the vote in the form (# yes, # no)
	 * @throws RemoteException, ClientNotFound, InterruptedException
	 */
	public String initiateEVote(String ballot) throws RemoteException, ClientNotFound, InterruptedException;
}
