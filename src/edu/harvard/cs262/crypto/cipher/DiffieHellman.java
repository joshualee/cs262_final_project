package edu.harvard.cs262.crypto.cipher;

import java.io.Serializable;
import java.math.BigInteger;
import java.rmi.RemoteException;
import java.util.Random;
import java.util.UUID;

import edu.harvard.cs262.crypto.CryptoMessage;
import edu.harvard.cs262.crypto.VPrint;
import edu.harvard.cs262.crypto.client.CryptoClient;
import edu.harvard.cs262.crypto.exception.ClientNotFound;

/**
 * Diffie Helman Key Exchange Protocol
 * 
 * http://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
 * 
 * @author Holly Anderson, Joshua Lee, and Tracy Lu
 */

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
		
		seed = (int) (Math.random() * 1000);
		rand = new Random(seed);
		id = UUID.randomUUID();
	}
	
	/**
	 * Seeds the KeyExchange protocol, which it uses to generate random numbers.
	 * This is helpful because it allows clients to ensure they are using their own
	 * unique seed.
	 * 
	 * @param seed 
	 * 		the seed	
	 */
	public void seed(long seed) {
		this.seed = seed;
		rand = new Random(seed);
	}
	
	public String getProtocolId() {
		return id.toString();
	}
	
	// for testing
	public UUID getFullProtocolId() {
		return id;
	}
	
	// for testing
	public void setProtocolId(UUID id) {
		this.id = id;
	}
	
	public int getBits() {
		return BITS;
	}
	
	/**
	 * Initiates DiffieHelman Key Exchange process. Blocks until another another client calls
	 * reciprocate using the same Key Exchange protocol (identified using the protocol ID).
	 * @param me
	 * 		The client initiating the Key Exchange process
	 * @param recipientName
	 * 		The client that "me" is trying to exchange with
	 * @return a Cryptokey containing both the public key and the shared private key that results from the key exchange process
	 * @throws RemoteException, ClientNotFound, InterruptedException
	 */
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
	
	/**
	 * Responds back when someone tries to start a DiffieHelman Key Exchange process with the client.
	 * Blocks until another another client call initiate using the same Key Exchange protocol
	 * (identified using the protocol ID).
	 * @param me
	 * 		The client initiating the Key Exchange process
	 * @param recipientName
	 * 		The client that "me" is trying to exchange with
	 * @return a Cryptokey containing both the public key and the shared private key that results from the key exchange process
	 * @throws RemoteException, ClientNotFound, InterruptedException
	 */
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
	
	/**
	 * Makes a copy of the current DiffieHellman protocol with the same public parameters and ID.
	 * This is needed when we want to perform a key exchange protocol on two clients that share the
	 * same JVM (because otherwise they would be modifying the same object).
	 * @return 
	 * 		the copy of the KeyExchangeProtocol
	 */
	public KeyExchangeProtocol copy() {
		DiffieHellman dh = new DiffieHellman();
		dh.setProtocolId(id);
		return dh;
	}
}