package edu.harvard.cs262.crypto;

import java.io.Serializable;
import java.math.BigInteger;
import java.rmi.RemoteException;
import java.util.Random;
import java.util.UUID;

public class DiffieHellman implements KeyExchangeProtocol, Serializable {
	private static final long serialVersionUID = 1L;
	
	// warning: making BITS > 31 
	private final int BITS = 31; 
	private final BigInteger P;
	private final BigInteger G;
	private long seed;
	private Random rand;
	private UUID id;
	
	public DiffieHellman() {
		P = BigInteger.valueOf(31123L);
		G = BigInteger.valueOf(2341L);
		
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
	
	public int getBits() {
		return BITS;
	}
	
	@Override
	public CryptoKey initiate(CryptoClient me, String recipientName) throws RemoteException, ClientNotFound, InterruptedException {
		me.getLog().print(VPrint.DEBUG, "%s initiating DiffieHellman with %s", me.getName(), recipientName);

		BigInteger x = new BigInteger(BITS, rand);
		BigInteger x_hat = G.modPow(x, P);
		
		me.sendMessage(recipientName, x_hat.toString(), getProtocolId());
		CryptoMessage inM = me.waitForMessage(getProtocolId());
		
		BigInteger y_hat = new BigInteger(inM.getPlainText());
		DHTuple publicKey = new DHTuple(P, G, y_hat);
		CryptoKey ck = new CryptoKey(x, publicKey, getBits());
		
		me.getLog().print(VPrint.DEBUG, "(%s) DiffieHellman exchange successful", me.getName());
		
		return ck;
	}

	@Override
	public CryptoKey reciprocate(CryptoClient me, String initiatorName) throws InterruptedException, RemoteException, ClientNotFound {
		me.getLog().print(VPrint.DEBUG, "%s reciprocating DiffieHellman with %s", me.getName(), initiatorName);
		
		BigInteger y = new BigInteger(BITS, rand);
		BigInteger y_hat = G.modPow(y, P);
		
		CryptoMessage m = me.waitForMessage(getProtocolId());
		me.sendMessage(initiatorName, y_hat.toString(), getProtocolId());
		
		BigInteger x_hat = new BigInteger(m.getPlainText());
		DHTuple publicKey = new DHTuple(P, G, x_hat);
		CryptoKey ck = new CryptoKey(y, publicKey, getBits());
		
		me.getLog().print(VPrint.DEBUG, "(%s) DiffieHellman exchange successful", me.getName());
		return ck;
	}
}