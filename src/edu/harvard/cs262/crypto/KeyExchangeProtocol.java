package edu.harvard.cs262.crypto;

import java.rmi.RemoteException;

public interface KeyExchangeProtocol {
	void seed(long seed);
	String getProtocolId();
	CryptoKey initiate(CryptoClient me, String recipientName) throws RemoteException, ClientNotFound, InterruptedException;
	CryptoKey reciprocate(CryptoClient me, String initiatorName) throws InterruptedException, RemoteException, ClientNotFound;
}
