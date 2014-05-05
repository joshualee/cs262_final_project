package edu.harvard.cs262.crypto.cipher;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Random;

import edu.harvard.cs262.crypto.CryptoMessage;
/** 
 * A full implementation of an El Gamal Cipher. We setup the key using DiffieHellman key exchange.
 * Has the ability to encrypt Strings and integers. For now, we encrypt a String by encrypting
 * character by character. In the future, we will want to do something smarter like using
 * Base64 encoding.
 * 
 * http://en.wikipedia.org/wiki/ElGamal_encryption
 *
 * @author Holly Anderson, Joshua Lee, and Tracy Lu
 */
public class ElGamalCipher implements CryptoCipher, Serializable {
	private static final long serialVersionUID = 1L;
	private CryptoKey key;
	private long seed;
	private Random rand;
	
	public ElGamalCipher() {
		key = null;
		seed = (int) (Math.random() * 1000);
		rand = new Random(seed);
	}
	
	/**
	 * The seed used by the cipher's random number generator. Useful for clients
	 * who want to use their own unique seed.
	 * @param s
	 * 		the seed 
	 */
	public void seed(long s) {
		seed = s;
		rand = new Random(seed);
	}

	/**
	 * Sets the key used by the CryptoCipher.
	 * 
	 * @param 
	 * 		k the key to be used by the cipher
	 */
	public void setKey(CryptoKey k) {
		key = k;
	}

	/**
	 * Encrypts a message using the cipher's key. Later calling decrypt on the message
	 * recovers the original plaintext message when using the same cipher.
	 * 
	 * @param plaintext
	 * 		The message to be encrypted
	 * @return 
	 * 		The encrypted message
	 */
	public CryptoMessage encrypt(String plaintext) {
		DHTuple dht = (DHTuple) key.getPublic();
		
		BigInteger y = new BigInteger(key.getBits(), rand).mod(dht.p);
		BigInteger yhat = dht.g.modPow(y, dht.p);
		
		/*
		 * For now we encrypt character by character;
		 * future work is to use more standard practice
		 * such as Base64 encoding.
		 */
		char[] cs = plaintext.toCharArray();
		char[] new_cs = new char[cs.length];
		
		for (int i = 0; i < cs.length; i++) {
			BigInteger m = BigInteger.valueOf(cs[i]);
			BigInteger tmp = dht.xhat.modPow(y, dht.p).multiply(m).mod(dht.p);
			new_cs[i] = (char) tmp.intValue();
		}
		
		String ciphertext = new String(new_cs);
		CryptoMessage m = new CryptoMessage(plaintext, ciphertext, "");
		m.setEncryptionState(yhat);
		return m;
	}
	
	/**
	 * The same thing as encrypt, except takes an integer as input. This is convenient for
	 * evoting where the inputs are integers rather than strings.
	 * 
	 * @param plaintext
	 * 		The integer to be encrypted
	 * @return 
	 * 		The encrypted integer
	 */
	public CryptoMessage encryptInteger(BigInteger plaintext) {
		DHTuple dht = (DHTuple) key.getPublic();
		
		BigInteger y = new BigInteger(key.getBits(), rand).mod(dht.p);
		BigInteger yhat = dht.g.modPow(y, dht.p);
		
		BigInteger ciphertext = dht.xhat.modPow(y, dht.p).multiply(plaintext).mod(dht.p);
		
		CryptoMessage m = new CryptoMessage(plaintext.toString(), ciphertext.toString(), "");
		m.setEncryptionState(yhat);
		
		return m;
	}
	
	/**
	 * The same thing as decrypt, except takes an encrypted integer as input. This is convenient for
	 * evoting where the inputs are integers rather than strings.
	 * 
	 * @param plaintext
	 * 		The encrypted integer to be decrypted
	 * @return 
	 * 		The decrypted integer
	 */
	public String decryptInteger(CryptoMessage cm) {
		DHTuple dht = (DHTuple) key.getPublic();
		BigInteger x = (BigInteger) key.getPrivate();
		BigInteger yhat = (BigInteger) cm.getEncryptionState();
		
		BigInteger m = new BigInteger(cm.getCipherText());
			
		BigInteger decrypted = yhat.modPow(x, dht.p).modInverse(dht.p).multiply(m).mod(dht.p);
		
		return decrypted.toString();
	}

	/**
	 * Decrypts an encrypted message that was originally encrypted using this cipher's
	 * encrypt function 
	 * @param cm
	 * 		the encrypted message to be decrypted 
	 * @return
	 * 		the decoded plaintext
	 */
	public String decrypt(CryptoMessage cm) {
		DHTuple dht = (DHTuple) key.getPublic();
		BigInteger x = (BigInteger) key.getPrivate();
		BigInteger yhat = (BigInteger) cm.getEncryptionState();
		
		/** 
		 * For now we encrypt character by character;
		 * future work is to use more standard practice
		 * such as Base64 encoding.
		 */
		char[] cs = cm.getCipherText().toCharArray();
		char[] new_cs = new char[cs.length];
		
		for (int i = 0; i < cs.length; i++) {
			BigInteger m = BigInteger.valueOf(cs[i]);
			
			BigInteger tmp = yhat.modPow(x, dht.p).modInverse(dht.p).multiply(m).mod(dht.p);
			new_cs[i] = (char) tmp.intValue();
		}
		
		String plaintext = new String(new_cs);
		
		return plaintext;
	}

	/**
	 * Makes a copy of the current cipher (does NOT copy the key)
	 * This is needed when we want to perform a key exchange
	 * protocol on two clients that share the same JVM (because otherwise they would be modifying the same object).
	 * @return 
	 * 		a copy of the current CryptoCipher with no key
	 */
	public CryptoCipher copy() {
		ElGamalCipher eg = new ElGamalCipher();
		return eg;
	}
}