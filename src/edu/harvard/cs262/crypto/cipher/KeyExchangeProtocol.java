package edu.harvard.cs262.crypto.cipher;

import java.rmi.RemoteException;

import edu.harvard.cs262.crypto.client.CryptoClient;
import edu.harvard.cs262.crypto.exception.ClientNotFound;
/**
 * Interface for key exchange protocols which allow two clients to securely exchange a private key
 * using publicly known communication. This interface is written in such a way that we are able
 * to encapsulate all key exchange logic within the key exchange class, so it doesn't spill into
 * the client logic. This allows clients to flexibly use different key exchange protocols
 * as desired. However, this requires that key exchange protocols know about clients and 
 * understand how to synchronously send messages to clients (see CryptoClient).
 *
 * @author Holly Anderson, Joshua Lee, and Tracy Lu
 */
public interface KeyExchangeProtocol {
	/**
	 * Seeds the KeyExchange protocol, which it uses to generate random numbers.
	 * This is helpful because it allows clients to ensure they are using their own
	 * unique seed.
	 * 
	 * @param seed 
	 * 		the seed	
	 */
	void seed(long seed);
	
	String getProtocolId();
	int getBits();
	
	/**
	 * Initiates Key Exchange process. Blocks until another another client calls
	 * reciprocate using the same Key Exchange protocol (identified using the protocol ID).
	 * @param me
	 * 		The client initiating the Key Exchange process
	 * @param recipientName
	 * 		The client that "me" is trying to exchange with
	 * @return a Cryptokey containing both the public key and the shared private key that results from the key exchange process
	 * @throws RemoteException, ClientNotFound, InterruptedException
	 */
	CryptoKey initiate(CryptoClient me, String recipientName) throws RemoteException, ClientNotFound, InterruptedException;
	
	/**
	 * Responds back when someone tries to start a Key Exchange with the client.
	 * Blocks until another another client call initiate using the same Key Exchange protocol
	 * (identified using the protocol ID).
	 * @param me
	 * 		The client initiating the Key Exchange process
	 * @param recipientName
	 * 		The client that "me" is trying to exchange with
	 * @return a Cryptokey containing both the public key and the shared private key that results from the key exchange process
	 * @throws RemoteException, ClientNotFound, InterruptedException
	 */
	CryptoKey reciprocate(CryptoClient me, String initiatorName) throws InterruptedException, RemoteException, ClientNotFound;
	
	/**
	 * Makes a copy of the current DiffieHellman protocol with the same public parameters and ID.
	 * This is needed when we want to perform a key exchange protocol on two clients that share the
	 * same JVM (because otherwise they would be modifying the same object).
	 * @return 
	 * 		the copy of the KeyExchangeProtocol
	 */
	KeyExchangeProtocol copy();
}