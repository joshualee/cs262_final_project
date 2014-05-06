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
 * Clients may also eavesdrop on other clients, simulating an attacker listening
 * to the wire. Client messages are relayed through a central server in order for
 * features such as notifications (eavesdropping) and evoting to work properly.  
 *
 * @author Holly Anderson, Joshua Lee, and Tracy Lu
 */

public interface CryptoClient extends Remote {
	/**
	 * Getter for client name
	 * @return the name of the client
	 * @throws RemoteException
	 */
	public String getName() throws RemoteException;
	
	/**
	 * The message history that the client can use to view messages received in the past.
	 * @return the message history as a map: (to, from) => list of messages
	 * @throws RemoteException
	 */
	public Map<ClientPair, List<CryptoMessage>> getMessages() throws RemoteException;
	
	/**
	 * Expose log so other modules can log actions
	 * 
	 * @return the logging object 
	 * @throws RemoteException
	 */
	public VPrint getLog() throws RemoteException;
	
	/**
	 * To detect whether the client has failed
	 * 
	 * @return true (client responded) 
	 * @throws RemoteException
	 */
	public boolean ping() throws RemoteException;
	
	/*
	 * Handlers for client to send/receive messages
	 */
	
	/**
	 * Receive a message sent from client "from" to client "to" and print it to the console.
	 * Note that "to" may not be the current client if the current client
	 * is eavesdropping on another client's communication.
	 * 
	 * @param from
	 * 		Who is sending the message
	 * @param to
	 * 		Who the message is for
	 * @param m
	 * 		The message (can only be non-encrypted for this simple client, may be encrypted for others)	
	 * @return the message that is received
	 * @throws RemoteException, InterruptedException
	 */
	String recvMessage(String from, String to, CryptoMessage m) throws RemoteException, InterruptedException;
	
	/**
	 * Send a message to client "to" by telling the server to do it.
	 * This function returns the plaintext of a message received as a string in order to:
	 * (1) do unit testing (2) ensure the correct message was sent.
	 *  
	 * @param to
	 * 		Who the message is for
	 * @param sid
	 * 		The session id of this communication
	 * @return the plaintext (or cipher text if not decryptable) of the sent message
	 * @throws RemoteException, InterruptedException
	 */
	String sendMessage(String to, String msg, String sid) throws RemoteException, ClientNotFound, InterruptedException;
	
	/**
	 * A wrapper for sendMessage that uses the proper cipher to first encrypt the message,
	 * and then calls sendMessage. If no cipher is set up with the recipient, automatically
	 * sets up the cipher first, then sends the encrypted message.
	 *    
	 * @param to
	 * 		Who the message is for
	 * @param sid
	 * 		The session id of this communication
	 * @return the plaintext (or cipher text if not decryptable) of the sent message
	 * @throws RemoteException, ClientNotFound, InterruptedException
	 */
	String sendEncryptedMessage(String to, String text, String sid) throws RemoteException, ClientNotFound, InterruptedException;
	
	/**
	 * Waits for a message from a certain session ID. Messages are placed into the map via
	 * the receive message function. This function is very important for key exchange where
	 * synchronous "conversations" are needed.
	 * 
	 * @param sid
	 * 		The session id of the awaited communication
	 * @return the message that you waited for
	 * @throws RemoteException, InterruptedException
	 */
	CryptoMessage waitForMessage(String sid) throws RemoteException, InterruptedException;
	
	/*
	 * Handlers for client to eavesdrop and stop eavesdropping on other clients
	 */
	
	/**
	 * "Eavesdrop" on another client. Register with the server to receive another client's
	 * communication. This simulates an attacker listening on the wire.
	 * 
	 * @param victim
	 * 		The client that you want to eavesdrop on
	 * @throws RemoteException
	 */
	void eavesdrop(String victim) throws RemoteException, ClientNotFound;
	
	/**
	 * Stop eavesdropping on a client. Unregister with the server to stop receiving another client's
	 * communication.
	 * @param victim
	 * 		The client that you want to stop eavesdropping on
	 * @throws RemoteException
	 */
	void stopEavesdrop(String victim) throws RemoteException, ClientNotFound;
	
	/*
	 * Handlers for client to set up key exchange protocol with another client
	 */
	
	/**
	 * Setup a secure channel with client "recip" using the KeyExchangeProtocol "kx" and
	 * CryptoCipher "cipher". This means that future communications with "recip" can be encrypted
	 * using "cipher", using the secret key generated by "kx". This function will initiate
	 * both sides of the key exchange process (on both the initiator and recipient sides).
	 *  
	 * @param counterParty
	 * 		The client you want to setup the secure channel up with
	 * @param kx
	 * 		The key exchange protocol being used
	 * @param cipher
	 * 		The cipher being used
	 * @return true if initialization is successful, otherwise false
	 * @throws RemoteException, ClientNotFound, InterruptedException
	 */
	public boolean initSecureChannel(String counterParty, KeyExchangeProtocol kx, CryptoCipher cipher) throws RemoteException, ClientNotFound, InterruptedException;
	
	/**
	 * Receive the request for setting up a shared secret key through a secure channel
	 * Reciprocate a request to setup a secure channel. If this call is successful, 
	 * then subsequent communications with client "counterParty" may be encrypted using
	 * the CrytoCipher "cipher" with the key generated by KeyExchangeProtocol "kx"
	 * (see initSecureChannel).
	 * 
	 * @param counterparty
	 * 		The client trying to set up the secure channel with you
	 * @param kx
	 * 		The key exchange protocol being used
	 * @param cipher
	 * 		The cipher being used
	 * @throws RemoteException, ClientNotFound, InterruptedException
	 */
	public void recvSecureChannel(String counterParty, KeyExchangeProtocol kx, CryptoCipher cipher) throws RemoteException, InterruptedException, ClientNotFound;
	
	/*
	 * Handlers for client to abort an e-vote if one if the other clients fail
	 */
	
	/**
	 * Aborts an evote, if client is currently engaged in one. An evote will be aborted by the server
	 * if any of the clients crash or take too long to respond. 
	 * 
	 * @param reason
	 * 		The reason that the evote needs to be aborted
	 * @throws RemoteException
	 */
	void evoteAbort(String reason) throws RemoteException;
	
	/**
	 * Participate in an evote started by the server. Client is expected to vote yes or no, and then
	 * will go through the steps of the evoting protocol in order to securely submit his vote as well
	 * as decrypt the result of the vote.
	 *  
	 * @param evote
	 * 		The evote to participate in
	 * @throws RemoteException, ClientNotFound, InterruptedException, EVoteInvalidResult
	 */
	public void evote(EVote evote) throws RemoteException, ClientNotFound, InterruptedException, EVoteInvalidResult;
}
