package edu.harvard.cs262.crypto;

import java.util.Random;

public class DiffieHellman implements KeyExchangeProtocol {
	
	private final int P = 23;
	private final int G = 5;
	private long seed;
	private Random rand;
	
	public DiffieHellman() {
		seed = 262; // by default use random seed
		rand = new Random(seed);
	}
	
	@Override
	public void seed(long seed) {
		this.seed = seed;
		rand = new Random(seed);
	}

	public void begin(CryptoClient c1, CryptoClient c2) throws KeyExchangeNotSupported {
		if (!c1.supportsKeyExchange(this.getClass()) || 
				!c2.supportsKeyExchange(this.getClass())) {
			throw new KeyExchangeNotSupported("DiffieHellman");
		}
		
		
	}

	@Override
	public String header() {
		// TODO Auto-generated method stub
		return null;
	}
	
	@Override
	public int initiate(CryptoClient me, String recipientName) {
		me.
		
		
		
		int x = rand.nextInt();
		int x_hat = MathHelpers.expmod(G, x, P);
		
		me.sendMessage(recipientName, Integer.toString(x_hat));
		CryptoMessage inM = me.waitForMessage(recipientName);
		
		int y_hat = Integer.parseInt(inM.getPlainText());
		int k = MathHelpers.ipow(y_hat, x);
		
		return k;
	}

	@Override
	public int reciprocate(CryptoClient me, String initiatorName) {
		int y = rand.nextInt();
		int y_hat = MathHelpers.expmod(G, y, P);
		
		CryptoMessage m = me.waitForMessage(initiatorName);
		me.sendMessage(initiatorName, Integer.toString(y_hat));
		
		return y_hat;
	}

}