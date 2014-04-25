package edu.harvard.cs262.crypto;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Random;

import javax.crypto.Cipher;

// Note: doesn't compile on my machine (Holly)
//import com.sun.org.apache.xml.internal.security.utils.Base64;

public class ElGamalCipher implements CryptoCipher, Serializable {
	private static final long serialVersionUID = 1L;
	private CryptoKey key;
	private long seed;
	private Random rand;
	
	public ElGamalCipher() {
		key = null;
		seed = 262;
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
		System.out.println(String.format("Encrypting: %s", plaintext));
		DHTuple dht = (DHTuple) key.getPublic();
		
//		System.out.println("Base64: " + Base64.encode(plaintext.getBytes()).);
		
		BigInteger y = new BigInteger(key.getBits(), rand).mod(dht.p);
		BigInteger yhat = dht.g.modPow(y, dht.p);
		
		char[] cs = plaintext.toCharArray();
		char[] new_cs = new char[cs.length];
		
		for (int i = 0; i < cs.length; i++) {
			BigInteger m = BigInteger.valueOf(cs[i]);
			BigInteger tmp = dht.xhat.modPow(y, dht.p).multiply(m).mod(dht.p);
			new_cs[i] = (char) tmp.intValue();
			System.out.println(String.format("cs[i]=%s, m=%s, tmp=%s, new_cs[i]=%s", cs[i], m.toString(), tmp.toString(), (int) new_cs[i]));
		}
		
		String ciphertext = new String(new_cs);
		CryptoMessage m = new CryptoMessage(plaintext, ciphertext, "");
		m.setEncryptionState(yhat);
		return m;
	}

	@Override
	public String decrypt(CryptoMessage cm) {
		DHTuple dht = (DHTuple) key.getPublic();
		BigInteger x = (BigInteger) key.getPrivate();
		BigInteger yhat = (BigInteger) cm.getEncryptionState();
		
		// for now, just decrypt each character separately
		char[] cs = cm.getCipherText().toCharArray();
		char[] new_cs = new char[cs.length];
		
		for (int i = 0; i < cs.length; i++) {
			BigInteger m = BigInteger.valueOf(cs[i]);
			
			BigInteger tmp = yhat.modPow(x, dht.p).modInverse(dht.p).multiply(m).mod(dht.p);
			new_cs[i] = (char) tmp.intValue();
			
			System.out.println(String.format("cs[i]=%s, m=%s, tmp=%s, new_cs[i]=%s", cs[i], m.toString(), tmp.toString(), new_cs[i]));
		}
		
		String plaintext = new String(new_cs);
		
		System.out.println(String.format("Decrypted: %s", plaintext));
		
		return plaintext;
	}

	@Override
	public void init(CryptoClient c1, CryptoClient c2) {
		// TODO Auto-generated method stub
		
	}
}