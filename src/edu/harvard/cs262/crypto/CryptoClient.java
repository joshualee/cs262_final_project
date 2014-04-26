package edu.harvard.cs262.crypto;

import java.rmi.Remote;
import java.rmi.RemoteException;

// All methods need to throw RemoteException in order for interface to be remote.
// Interface needs to be remote so a stub can be generated.
public interface CryptoClient extends Remote {
	public String getName() throws RemoteException;
	public void setName(String name) throws RemoteException;
	public boolean ping() throws RemoteException;
	
	/*
	 * Handlers for client to send/receive messages.
	 */
	void recvMessage(String from, String to, CryptoMessage m) throws RemoteException, InterruptedException;
	void sendMessage(String to, String msg, String sid) throws RemoteException, ClientNotFound, InterruptedException;
	void sendEncryptedMessage(String to, String text, String sid) throws RemoteException, ClientNotFound, InterruptedException;
	CryptoMessage waitForMessage(String sid) throws RemoteException, InterruptedException;
	
	void eavesdrop(String victim) throws RemoteException, ClientNotFound;
	
	public void initSecureChannel(String recip, KeyExchangeProtocol kx, CryptoCipher cipher) throws RemoteException, ClientNotFound, InterruptedException;
	public void recvSecureChannel(String counterParty, KeyExchangeProtocol kx, CryptoCipher cipher) throws RemoteException, InterruptedException, ClientNotFound;
		
//	boolean supportsKeyExchange(Class<?> keyExchange);
//	boolean supportsEncryptionScheme(Class<?> encryptionScheme);
}
