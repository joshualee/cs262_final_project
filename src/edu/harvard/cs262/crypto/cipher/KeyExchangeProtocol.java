package edu.harvard.cs262.crypto.cipher;

import java.rmi.RemoteException;

import edu.harvard.cs262.crypto.client.CryptoClient;
import edu.harvard.cs262.crypto.exception.ClientNotFound;

public interface KeyExchangeProtocol {
	void seed(long seed);
	String getProtocolId();
	int getBits();
	CryptoKey initiate(CryptoClient me, String recipientName) throws RemoteException, ClientNotFound, InterruptedException;
	CryptoKey reciprocate(CryptoClient me, String initiatorName) throws InterruptedException, RemoteException, ClientNotFound;
	
	/**
	 * Return a copy of the key exchange protocol. This is needed when we want to perform a key excahnge
	 * protocol on 
	 * @return
	 */
	KeyExchangeProtocol copy();
}