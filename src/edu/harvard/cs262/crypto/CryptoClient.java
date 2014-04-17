package edu.harvard.cs262.crypto;

public interface CryptoClient {
	
	/*
	 * Handler for client to receive messages.
	 */
	void receiveMessage(String from, Message m);

	/*
	 * Set up a secret key with client "clientName"
	 * using protocol of type "ptype" (e.g. Diffie Hellman).
	 * This is a wrapper for send/receive message calls which
	 * will send the information to set up the key
	 * (this allows eavesdroppers to also listen to this communication)
	 */
	void handshake(String clientName, ProtocolType ptype);

	boolean ping();

}
