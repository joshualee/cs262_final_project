package edu.harvard.cs262.crypto;

public interface KeyExchangeProtocol {
	void seed(long seed);
	
	String header();
	int initiate(CryptoClient me, String recipientName);
	int reciprocate(CryptoClient me, String initiatorName);
	
	void begin(CryptoClient c1, CryptoClient c2) throws KeyExchangeNotSupported;
}
