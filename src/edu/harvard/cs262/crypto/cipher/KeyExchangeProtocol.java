package edu.harvard.cs262.crypto.cipher;

import java.rmi.RemoteException;

import edu.harvard.cs262.crypto.client.CryptoClient;
import edu.harvard.cs262.crypto.exception.ClientNotFound;
/**
 * Interface for implementing different types of key exchange protocols
 *
 * @author Holly Anderson, Joshua Lee, and Tracy Lu
 */
public interface KeyExchangeProtocol {
	void seed(long seed);
	String getProtocolId();
	int getBits();
	CryptoKey initiate(CryptoClient me, String recipientName) throws RemoteException, ClientNotFound, InterruptedException;
	CryptoKey reciprocate(CryptoClient me, String initiatorName) throws InterruptedException, RemoteException, ClientNotFound;
	
	/**
	 * Returns a copy of the key exchange protocol. This is needed when we want to perform a key exchange
	 * protocol on two clients that share the same JVM (because otherwise they would be modifying the same object).
	 */
	KeyExchangeProtocol copy();
}