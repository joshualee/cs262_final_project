package edu.harvard.cs262.crypto;

import java.math.BigInteger;

public interface CryptoCipher {
	void seed(long s);
	
	void setKey(CryptoKey k);
	
	CryptoMessage encrypt(String plaintext);
	CryptoMessage encryptInteger(BigInteger plaintext);
	String decrypt(CryptoMessage cm);
	String decryptInteger(CryptoMessage cm);
}
