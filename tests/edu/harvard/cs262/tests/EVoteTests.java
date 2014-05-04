/**
 * JUnit tests for evoting.
 * Here we test that the result of the vote actually matches what we expect.
 */

package edu.harvard.cs262.tests;

import static org.junit.Assert.*;
import java.rmi.RemoteException;

import org.junit.BeforeClass;
import org.junit.Test;

import edu.harvard.cs262.crypto.client.EVoteClient;
import edu.harvard.cs262.crypto.exception.ClientNotFound;
import edu.harvard.cs262.crypto.server.EVoteServer;

public class EVoteTests {
	
	static EVoteServer server;
	static EVoteClient c1, c2, c3, c4, c5;
	
	@BeforeClass 
	public static void setup() {
		EVoteServer.setTimeout(1);
		
		// dummy server
		server = new EVoteServer("server"); 
		
		// dummy clients
		c1 = new EVoteClient("c1", server);
		c2 = new EVoteClient("c2", server);
		c3 = new EVoteClient("c3", server);
		c4 = new EVoteClient("c4", server);
		c5 = new EVoteClient("c5", server);
		
		try {
			server.registerClient(c1);
			server.registerClient(c2);
			server.registerClient(c3);
			server.registerClient(c4);
		} catch (RemoteException e) {
			fail("client registration failed");
		}
	}
	
	@Test
	public void basicEvote() throws RemoteException, ClientNotFound, InterruptedException {
		c1.setTestVote(1);
		c2.setTestVote(0);
		c3.setTestVote(1);
		c4.setTestVote(0);
		
		String result = server.initiateEVote("test ballot");		
		assertEquals("(2,2)", result);
		
		// ensure we allow consecutive evotes successfully
		
		c1.setTestVote(0);
		c2.setTestVote(1);
		c3.setTestVote(0);
		c4.setTestVote(1);
		
		String result2 = server.initiateEVote("second test ballot");		
		assertEquals("(2,2)", result2);
	}
	
	@Test
	public void unregisterEvote() throws RemoteException, ClientNotFound, InterruptedException {
		server.unregisterClient(c1.getName());
		
		c2.setTestVote(0);
		c3.setTestVote(0);
		c4.setTestVote(0);
		
		String result = server.initiateEVote("another test ballot");
		assertEquals("(0,3)", result);
	}
	
	@Test
	public void newRegisterEvote() throws RemoteException, ClientNotFound, InterruptedException {
		server.registerClient(c5);
		
		c2.setTestVote(1);
		c3.setTestVote(1);
		c4.setTestVote(1);
		c5.setTestVote(1);
		
		String result = server.initiateEVote("yet another test ballot");
		assertEquals("(4,0)", result);
	}
	
	@Test
	public void failedEvote() throws RemoteException, ClientNotFound, InterruptedException {
		// supply c2 an invalid vote, causing him to block and the vote to take too long
		c2.setTestVote(2);
		c3.setTestVote(1);
		c4.setTestVote(0);
		c5.setTestVote(1);
		String result = server.initiateEVote("should fail test ballot");
		
		assertEquals("", result);
	}

}
