package edu.harvard.cs262.crypto.cipher;

import java.math.BigInteger;

import edu.harvard.cs262.crypto.CryptoMessage;
/**
 * Interface for implementing different types of encryption/decryption ciphers
 *
 * @author Holly Anderson, Joshua Lee, and Tracy Lu
 */
public interface CryptoCipher {
	
	/**
	 * The seed used by the cipher's random number generator. Useful for clients
	 * who want to use their own unique seed.
	 * @param s
	 * 		the seed 
	 */
	void seed(long s);
	
	/**
	 * Sets the key used by the CryptoCipher
	 * 
	 * @param 
	 * 		k the key to be used by the cipher
	 */
	void setKey(CryptoKey k);
	
	/**
	 * Encrypts a message using the cipher's key. Later calling decrypt on the message
	 * recovers the original plaintext message when using the same cipher.
	 * 
	 * @param plaintext
	 * 		The message to be encrypted
	 * @return the encrypted message
	 */
	CryptoMessage encrypt(String plaintext);
	
	
	/**
	 * The same thing as encrypt, except takes an integer as input. This is convenient for
	 * evoting where the inputs are integers rather than strings.
	 * 
	 * @param plaintext
	 * 		The integer to be encrypted
	 * @return the encrypted integer
	 */
	CryptoMessage encryptInteger(BigInteger plaintext);
	
	/**
	 * Decrypts an encrypted message that was originally encrypted using this cipher's
	 * encrypt function 
	 * @param cm
	 * 		The encrypted message to be decrypted 
	 * @return the decoded plaintext
	 */
	String decrypt(CryptoMessage cm);
	
	/**
	 * The same thing as decrypt, except takes an encrypted integer as input. This is convenient for
	 * evoting where the inputs are integers rather than strings.
	 * 
	 * @param plaintext
	 * 		The encrypted integer to be decrypted
	 * @return the decrypted integer
	 */
	String decryptInteger(CryptoMessage cm);
	
	/**
	 * Makes a copy of the current cipher (does NOT copy the key)
	 * This is needed when we want to perform a key exchange protocol on two clients
	 * that share the same JVM (because otherwise they would be modifying the same object).
	 * @return a copy of the current CryptoCipher with no key
	 */
	CryptoCipher copy();
}
