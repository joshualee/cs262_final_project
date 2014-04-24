package edu.harvard.cs262.crypto;

import java.io.Serializable;
import java.math.BigInteger;
import java.rmi.RemoteException;
import java.util.Random;
import java.util.UUID;

public class DiffieHellman implements KeyExchangeProtocol, Serializable {
	private static final long serialVersionUID = 1L;
	
	private final int BITS = 32; 
	private final BigInteger P;
	private final BigInteger G;
	private long seed;
	private Random rand;
	private UUID id;
	
	public DiffieHellman() {
		P = BigInteger.valueOf(23L);
		G = BigInteger.valueOf(5L);
		
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
		System.out.println(String.format("%s initiating DiffieHellman with %s", me.getName(), recipientName));
		System.out.println("here");
		BigInteger x = new BigInteger(BITS, rand);
		System.out.println("here1");
		
		BigInteger x_hat = G.modPow(x, P);
		System.out.println("here2");
		
		System.out.println(String.format("(%s) about to send x_hat", me.getName()));
		me.sendMessage(recipientName, x_hat.toString(), getProtocolId());
		CryptoMessage inM = me.waitForMessage(getProtocolId());
		
		BigInteger y_hat = new BigInteger(inM.getPlainText());
		BigInteger key = y_hat.pow(x.intValue());
		CryptoKey ck = new CryptoKey(key);
		
		return ck;
	}

	@Override
	public CryptoKey reciprocate(CryptoClient me, String initiatorName) throws InterruptedException, RemoteException, ClientNotFound {
		System.out.println(String.format("%s reciprocating DiffieHellman with %s", me.getName(), initiatorName));
		
		BigInteger y = new BigInteger(BITS, rand);
		BigInteger y_hat = G.modPow(y, P);
		
		CryptoMessage m = me.waitForMessage(getProtocolId());		
		me.sendMessage(initiatorName, y_hat.toString(), getProtocolId());
		
		BigInteger x_hat = new BigInteger(m.getPlainText());
		BigInteger key = x_hat.pow(y.intValue());
		CryptoKey ck = new CryptoKey(key);
		
		return ck;
	}
}