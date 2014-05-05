package edu.harvard.cs262.crypto.cipher;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Random;

import edu.harvard.cs262.crypto.CryptoMessage;
/** 
 * We used the El Gamal Cipher, which is implemented below.
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
	
	public void seed(long s) {
		seed = s;
		rand = new Random(seed);
	}

	public void setKey(CryptoKey k) {
		key = k;
	}

	/**
	 * Encrypts a message
	 * @param plaintext
	 * 		The message to be encrypted
	 * @return The encrypted message
	 */
	public CryptoMessage encrypt(String plaintext) {
		DHTuple dht = (DHTuple) key.getPublic();
		
		BigInteger y = new BigInteger(key.getBits(), rand).mod(dht.p);
		BigInteger yhat = dht.g.modPow(y, dht.p);
		
		/** 
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
	 * Encrypts an integer
	 * @param plaintext
	 * 		The integer to be encrypted
	 * @return The encrypted integer
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
	 * Decrypts a integer
	 * @param plaintext
	 * 		The integer to be decrypted
	 * @return The decrypted integer
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
	 * Decrypts a message
	 * @param plaintext
	 * 		The message to be decrypted
	 * @return The decrypted message
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
	 * Makes a copy of the current cipher
	 * This is needed when we want to perform a key exchange
	 * protocol on two clients that share the same JVM (because otherwise they would be modifying the same object).
	 * @return a copy of the current CryptoCipher
	 */
	public CryptoCipher copy() {
		ElGamalCipher eg = new ElGamalCipher();
		return eg;
	}
}