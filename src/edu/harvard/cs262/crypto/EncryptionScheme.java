package edu.harvard.cs262.crypto;

public interface EncryptionScheme {
	
	void seed(long s);
	KeyExchangeProtocol getKeyExchange();
	
	String encrypt(String plaintext);
	String decrypt(String ciphertext);
	
	void init(CryptoClient c1, CryptoClient c2);
}
