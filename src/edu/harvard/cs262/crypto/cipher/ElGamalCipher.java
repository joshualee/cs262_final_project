package edu.harvard.cs262.crypto.cipher;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Random;

import edu.harvard.cs262.crypto.CryptoMessage;

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
	
	@Override
	public void seed(long s) {
		seed = s;
		rand = new Random(seed);
	}

	@Override
	public void setKey(CryptoKey k) {
		key = k;
	}

	@Override
	public CryptoMessage encrypt(String plaintext) {
		DHTuple dht = (DHTuple) key.getPublic();
		
		BigInteger y = new BigInteger(key.getBits(), rand).mod(dht.p);
		BigInteger yhat = dht.g.modPow(y, dht.p);
		
		// for now we encrypt character by character
		// future work is to use more standard practice
		// such as Base64 encoding
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
	
	public CryptoMessage encryptInteger(BigInteger plaintext) {
		DHTuple dht = (DHTuple) key.getPublic();
		
		BigInteger y = new BigInteger(key.getBits(), rand).mod(dht.p);
		BigInteger yhat = dht.g.modPow(y, dht.p);
		
		BigInteger ciphertext = dht.xhat.modPow(y, dht.p).multiply(plaintext).mod(dht.p);
		
		CryptoMessage m = new CryptoMessage(plaintext.toString(), ciphertext.toString(), "");
		m.setEncryptionState(yhat);
		
		return m;
	}
	
	public String decryptInteger(CryptoMessage cm) {
		DHTuple dht = (DHTuple) key.getPublic();
		BigInteger x = (BigInteger) key.getPrivate();
		BigInteger yhat = (BigInteger) cm.getEncryptionState();
		
		BigInteger m = new BigInteger(cm.getCipherText());
			
		BigInteger decrypted = yhat.modPow(x, dht.p).modInverse(dht.p).multiply(m).mod(dht.p);
		
		return decrypted.toString();
	}

	@Override
	public String decrypt(CryptoMessage cm) {
		DHTuple dht = (DHTuple) key.getPublic();
		BigInteger x = (BigInteger) key.getPrivate();
		BigInteger yhat = (BigInteger) cm.getEncryptionState();
		
		// for now we decrypy character by character
		// future work is to use more standard practice
		// such as Base64 encoding
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

	@Override
	public CryptoCipher copy() {
		ElGamalCipher eg = new ElGamalCipher();
		return eg;
	}
}