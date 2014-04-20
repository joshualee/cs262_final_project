package edu.harvard.cs262.crypto;

import java.rmi.Remote;
import java.rmi.RemoteException;

// All methods need to throw RemoteException in order for interface to be remote.
// Interface needs to be remote so a stub can be generated.
public interface CryptoClient extends Remote{
	
	/*
	 * Handler for client to receive messages.
	 */
	void receiveMessage(String from, CryptoMessage m) throws RemoteException;
	void sendMessage(String to, String msg);
	
	void startSession();
	void endSession();
	
	CryptoMessage waitForMessage(String from);

	public String getName() throws RemoteException;

	public boolean ping() throws RemoteException;

	int random();
		
	boolean supportsKeyExchange(Class<?> keyExchange);
	boolean supportsEncryptionScheme(Class<?> encryptionScheme);
	

}
