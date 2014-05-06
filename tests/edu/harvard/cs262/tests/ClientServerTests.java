package edu.harvard.cs262.tests;

import static org.junit.Assert.*;
import java.rmi.RemoteException;

import org.junit.BeforeClass;
import org.junit.Test;

import edu.harvard.cs262.crypto.CryptoMessage;
import edu.harvard.cs262.crypto.client.CryptoClient;
import edu.harvard.cs262.crypto.client.DHCryptoClient;
import edu.harvard.cs262.crypto.exception.ClientNotFound;
import edu.harvard.cs262.crypto.server.CentralServer;
import edu.harvard.cs262.crypto.server.CryptoServer;

/**
 * JUnit tests for client server and client client interaction.
 * Here we test:
 * (1) Basic server functions
 * (2) Basic client functions
 * (3) Synchronization with waitMessage()
 * 
 * More advanced client and server functions are tested in ConsoleTest.java
 *
 * @author Holly Anderson, Joshua Lee, and Tracy Lu
 */
public class ClientServerTests {

	static CryptoServer server;
	static DHCryptoClient c1, c2, c3;
	
	@BeforeClass 
	public static void setup() {
		// dummy server
		server = new CentralServer("server"); 
		
		// dummy clients
		c1 = new DHCryptoClient("c1", server);
		c2 = new DHCryptoClient("c2", server);
		c3 = new DHCryptoClient("c3", server);
		
		try {
			server.registerClient(c1);
			server.registerClient(c2);
			server.registerClient(c3);
		} catch (RemoteException e) {
			fail("client registration failed");
		}
	}
	
	@Test
	public void basicServer() throws RemoteException, ClientNotFound {
		
		// basic server functions
		
		String serverName = server.getName();
		assertEquals("server", serverName);
		
		String clientList = server.getClientList(true);
		assertEquals("[c1, c2, c3]", clientList);
		
		CryptoClient c1Server = server.getClient("c3");
		assertEquals(c3, c1Server);
		
		// look for a non existent client	
		try {
			server.getClient("fake client name");
			fail("client should not exist");
		} catch (ClientNotFound e) {
			// success!
			assertTrue(true);
		}
		
		// unregister client and make sure he no longer exists		
		server.unregisterClient(c3.getName());
		
		try {
			server.getClient(c3.getName());
			fail("client should not exist");
		} catch (ClientNotFound e) {
			// success!
			assertTrue(true);
		}		
		
		// other server functionality tested in other JUnit files and ConsoleTest.java
	}
	
	@Test
	public void basicClient() {
		String clientName = c1.getName();
		assertEquals("c1", clientName);
		
		// other client functionality tested in ConsoleTest.java, CryptoCipherTest.java, EVoteTest.java, and below
	}
	
	@Test
	public void waitMessages() throws RemoteException, InterruptedException {
		String msg = "hello";
		String session = "test session";
		
		c1.sendMessage(c2.getName(), msg, session);
		CryptoMessage m = c2.waitForMessage(session);
		
		assertEquals(msg, m.getPlainText());
		
		String msg2 = "another hello";
		String session2 = "another test session";
		
		c2.sendMessage(c1.getName(), msg2, session2);
		CryptoMessage m2 = c1.waitForMessage(session2);
		
		assertEquals(msg2, m2.getPlainText());
	}
}
