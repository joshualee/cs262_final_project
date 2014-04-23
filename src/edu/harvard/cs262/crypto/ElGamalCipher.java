package edu.harvard.cs262.crypto;

import java.math.BigInteger;
import java.util.Random;

import javax.crypto.Cipher;

public class ElGamalCipher implements CryptoCipher {
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
		DHTuple dht = (DHTuple) key.getPublic();
		int y = (int) (rand.nextInt() % dht.p);
		int y_hat = MathHelpers.expmod(dht.g, y, dht.p);
		
		char[] cs = plaintext.toCharArray();
		char[] new_cs = new char[cs.length];
		
		for (int i = 0; i < cs.length; i++) {
			int m = cs[i];
			
			new_cs[i] = (char) ((MathHelpers.ipow(dht.xhat, y) * m) % dht.p);
		}
		
		String ciphertext = new String(new_cs);
		
		CryptoMessage m = new CryptoMessage(plaintext, ciphertext, "");
		m.setEncryptionState(new Integer(y_hat));
		
		return m;
	}

	@Override
	public String decrypt(CryptoMessage cm) {
		DHTuple dht = (DHTuple) key.getPublic();
		int x = (Integer) key.getPrivate();
		int yhat = (Integer) cm.getEncryptionState();
		
		// for now, just decrypt each character separately
		char[] cs = cm.getCipherText().toCharArray();
		char[] new_cs = new char[cs.length];
		
		for (int i = 0; i < cs.length; i++) {
			int m = cs[i];
			
			// for now, convert to BigInteger to use modInverse
			int tmp = MathHelpers.ipow(yhat, x);
			BigInteger bigTmp = BigInteger.valueOf((long)tmp);
			bigTmp = bigTmp.modInverse(BigInteger.valueOf((long)dht.p));
			
			new_cs[i] = (char) ((bigTmp.intValue() * m) % dht.p);
		}
		
		String plaintext = new String(new_cs);
		
		return plaintext;
	}

	@Override
	public void init(CryptoClient c1, CryptoClient c2) {
		// TODO Auto-generated method stub
		
	}
}