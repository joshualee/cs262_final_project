package edu.harvard.cs262.crypto;

import java.rmi.Remote;
import java.rmi.RemoteException;

// All methods need to throw RemoteException in order for interface to be remote.
// Interface needs to be remote so a stub can be generated.
public interface CryptoServer extends Remote{
	
	public String getName();
	
	/*
	 * Register client so server can forward it messages.
	 */
	public boolean registerClient(CryptoClient c) throws RemoteException;
	public boolean unregisterClient(String clientName) throws RemoteException;

	/* 
	 * Allow client "eve" to listen to all incoming
	 * and outgoing communication of client "victim"
	 */
	public void eavesdrop(String eve, String victim) throws RemoteException, ClientNotFound;
	public void stopEavesdrop(String eve, String victim) throws RemoteException, ClientNotFound;

	/*
	 * Send message "m" from client "from" to client "to".
	 * Blocks until message has successfully been delivered.
	 */
	public void sendMessage(String from, String to, CryptoMessage m) throws RemoteException, ClientNotFound, InterruptedException;
	
	
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
	public void recvMessage(String from, CryptoMessage m) throws RemoteException, ClientNotFound, InterruptedException;
	
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

	/*
	 * Return reference to client
	 */
	CryptoClient getClient(String clientName) throws RemoteException, ClientNotFound;

	public boolean ping() throws RemoteException;

}
