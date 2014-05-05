package edu.harvard.cs262.crypto.cipher;

import java.math.BigInteger;

import edu.harvard.cs262.crypto.CryptoMessage;
/**
 * Interface for implementing different types of ciphers
 *
 */
public interface CryptoCipher {
	void seed(long s);
	
	void setKey(CryptoKey k);
	
	CryptoMessage encrypt(String plaintext);
	CryptoMessage encryptInteger(BigInteger plaintext);
	String decrypt(CryptoMessage cm);
	String decryptInteger(CryptoMessage cm);
	CryptoCipher copy();
}
