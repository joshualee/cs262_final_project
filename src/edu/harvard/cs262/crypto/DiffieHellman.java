package edu.harvard.cs262.crypto;

import java.rmi.RemoteException;
import java.util.Random;
import java.util.UUID;

public class DiffieHellman implements KeyExchangeProtocol {
	private final int P = 23;
	private final int G = 5;
	private long seed;
	private Random rand;
	private UUID id;
	
	public DiffieHellman() {
		seed = 262;
		rand = new Random(seed);
		id = UUID.randomUUID();
	}
	
	@Override
	public void seed(long seed) {
		this.seed = seed;
		rand = new Random(seed);
	}
	
	@Override
	public String getProtocolId() {
		return id.toString();
	}
	
	@Override
	public CryptoKey initiate(CryptoClient me, String recipientName) throws RemoteException, ClientNotFound, InterruptedException {
		int x = rand.nextInt();
		int x_hat = MathHelpers.expmod(G, x, P);
		
		me.sendMessage(recipientName, Integer.toString(x_hat), getProtocolId());
		CryptoMessage inM = me.waitForMessage(getProtocolId());
		
		int y_hat = Integer.parseInt(inM.getPlainText());
		int key = MathHelpers.ipow(y_hat, x);
		CryptoKey ck = new CryptoKey(key);
		
		return ck;
	}

	@Override
	public CryptoKey reciprocate(CryptoClient me, String initiatorName) throws InterruptedException, RemoteException, ClientNotFound {
		int y = rand.nextInt();
		int y_hat = MathHelpers.expmod(G, y, P);
		
		CryptoMessage m = me.waitForMessage(getProtocolId());		
		me.sendMessage(initiatorName, Integer.toString(y_hat), getProtocolId());
		
		int x_hat = Integer.parseInt(m.getPlainText());
		int key = MathHelpers.ipow(x_hat, y);
		CryptoKey ck = new CryptoKey(key);
		
		return ck;
	}
}