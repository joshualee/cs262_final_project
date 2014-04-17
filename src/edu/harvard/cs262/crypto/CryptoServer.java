package edu.harvard.cs262.crypto;

public interface CryptoServer {
	
	/*
	 * Register client so server can forward it messages.
	 */
	boolean registerClient(Client c)
	boolean unregisterClient(String clientName)

	/* 
	 * Allow client "eve" to listen to all incoming
	 * and outgoing communication of client "victim"
	 */
	void eavesdrop(String eve, String victim) throws ClientNotFound
	void stopEavesdrop(String eve, String victim) throws ClientNotFound

	/*
	 * Send message "m" from client "from" to client "to".
	 * Blocks until message has successfully been delivered.
	 */
	void sendMessage(String from, String to, Message m)

	/*
	 * Return reference to client
	 */
	Client getClient(String clientName);

	boolean ping();

}
