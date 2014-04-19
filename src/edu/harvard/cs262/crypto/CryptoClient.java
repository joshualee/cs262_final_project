package edu.harvard.cs262.crypto;

import java.rmi.Remote;
import java.rmi.RemoteException;

// All methods need to throw RemoteException in order for interface to be remote.
// Interface needs to be remote so a stub can be generated.
public interface CryptoClient extends Remote{
	
	/*
	 * Handler for client to receive messages.
	 */
	public void receiveMessage(String from, CryptoMessage m) throws RemoteException;

	/*
	 * Set up a secret key with client "clientName"
	 * using protocol of type "ptype" (e.g. Diffie Hellman).
	 * This is a wrapper for send/receive message calls which
	 * will send the information to set up the key
	 * (this allows eavesdroppers to also listen to this communication)
	 */
	public void handshake(String clientName, ProtocolType ptype) throws RemoteException;

	public String getName() throws RemoteException;

	public boolean ping() throws RemoteException;

}
