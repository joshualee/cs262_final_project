package edu.harvard.cs262.crypto.server;

import java.rmi.Remote;
import java.rmi.RemoteException;

import edu.harvard.cs262.crypto.CryptoMessage;
import edu.harvard.cs262.crypto.cipher.CryptoCipher;
import edu.harvard.cs262.crypto.cipher.KeyExchangeProtocol;
import edu.harvard.cs262.crypto.client.CryptoClient;
import edu.harvard.cs262.crypto.exception.ClientNotFound;

// All methods need to throw RemoteException in order for interface to be remote.
// Interface needs to be remote so a stub can be generated.
public interface CryptoServer extends Remote {
	
	String getName() throws RemoteException;
	
	String getClientList(boolean arrayFormat) throws RemoteException;
	
	/*
	 * Return reference to client
	 */
	CryptoClient getClient(String clientName) throws RemoteException, ClientNotFound;
	
	public boolean ping() throws RemoteException;
	
	/*
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
	 * @throws RemoteException
	 * @throws ClientNotFound
	 * @throws InterruptedException 
	 */
	public String recvMessage(String from, String to, CryptoMessage m) throws RemoteException, ClientNotFound, InterruptedException;
	
	/*
	 * Send message "m" from client "from" to client "to".
	 * Blocks until message has successfully been delivered.
	 */
	public String sendMessage(String from, String to, CryptoMessage m) throws RemoteException, ClientNotFound, InterruptedException;
	
		/* 
	 * Allow client "listener" to listen to all incoming
	 * and outgoing communication of client "victim"
	 */
	public void eavesdrop(String listener, String victim) throws RemoteException, ClientNotFound;
	public void stopEavesdrop(String listener, String victim) throws RemoteException, ClientNotFound;
	
	/**
	 * 
	 * @param from
	 * @param to
	 * @param m
	 * @throws ClientNotFound 
	 * @throws RemoteException 
	 * @throws InterruptedException 
	 */
	public void relaySecureChannel(String from, String to, KeyExchangeProtocol kx, CryptoCipher c) throws ClientNotFound, RemoteException, InterruptedException;

	public void initiateEVote(String ballot) throws RemoteException, ClientNotFound, InterruptedException;
}
