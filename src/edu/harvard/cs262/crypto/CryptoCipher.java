package edu.harvard.cs262.crypto;

public interface CryptoCipher {
	void seed(long s);
	
	void setKey(CryptoKey k);
	
	CryptoMessage encrypt(String plaintext);
	String decrypt(CryptoMessage cm);
	
	void init(CryptoClient c1, CryptoClient c2);
}
