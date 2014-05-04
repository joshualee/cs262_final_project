package edu.harvard.cs262.tests;

import java.net.InetAddress;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.util.UUID;

import edu.harvard.cs262.crypto.client.CryptoClient;
import edu.harvard.cs262.crypto.client.DHCryptoClient;
import edu.harvard.cs262.crypto.exception.ClientNotFound;
import edu.harvard.cs262.crypto.server.CentralServer;
import edu.harvard.cs262.crypto.server.CryptoServer;

/**
 * Basic tests of interactions between DHCryptoClient and CentralServer classes;
 *  i.e. tests functionality of ClientConsole.java.
 *
 * @author joshualee and Holly Anderson
 *
 */

public class BasicTest {
	
	private static String rmiHost;
	private final static int rmiPort = 8080;
	private final static String serverName = "TestServer";
	
	private static void setupServer() throws RemoteException {
		CentralServer server = new CentralServer(serverName);
		CryptoServer serverStub = (CryptoServer) UnicastRemoteObject.exportObject(server, 0);

		// create registry so we don't have to manually start
		// the registry server elsewhere
		Registry registry = LocateRegistry.createRegistry(rmiPort);
		
		// rebind to avoid AlreadyBoundException
		registry.rebind(serverName, serverStub);
	}
	
	private static CryptoClient createClient(String name, CryptoServer server) throws RemoteException {
		CryptoClient myClient = new DHCryptoClient(name, server);
		CryptoClient myClientSer = ((CryptoClient)UnicastRemoteObject.exportObject(myClient, 0));
		
		server.registerClient(myClientSer);
		return myClient;
	}
	
	private static void sendRandomMessages(CryptoClient c1, CryptoClient c2, int numMessages) throws RemoteException, ClientNotFound, InterruptedException {
		for (int i = 0; i < numMessages; i++) {
			String uuid1 = UUID.randomUUID().toString();
			c1.sendMessage(c2.getName(), uuid1, "");
		}
	}
	
	private static void sendRandomEncMessages(CryptoClient c1, CryptoClient c2, int numMessages) throws RemoteException, ClientNotFound, InterruptedException {
		for (int i = 0; i < numMessages; i++) {
			String uuid1 = UUID.randomUUID().toString();
			c1.sendEncryptedMessage(c2.getName(), uuid1, "");
		}
	}

	public static void main(String args[]) {		
		try {
			rmiHost = InetAddress.getLocalHost().getHostAddress();
			System.setProperty("java.security.policy", "policies/all.policy");
			
			if (System.getSecurityManager() == null) {
				System.setSecurityManager(new SecurityManager());
			}
			
			setupServer();
			Registry registry = LocateRegistry.getRegistry(rmiHost, rmiPort);
			CryptoServer server = (CryptoServer) registry.lookup(serverName);
			
			System.out.println("Registering Clients");
			System.out.println("===================");
			CryptoClient c1 = createClient("c1", server);
			CryptoClient c2 = createClient("c2", server);
			CryptoClient e1 = createClient("e1", server);
			CryptoClient e2 = createClient("e2", server);
			System.out.println("===================\n");
			
			// =========================================			
			// TEST1
			// =========================================
			System.out.println("e1 eavesdrops on c1");
			System.out.println("===================");
			e1.eavesdrop(c1.getName());
			System.out.println("===================\n");
				
			System.out.println("Sending Messages");
			System.out.println("===================");
			// 1 pair of identical lines of messages: 1 on e1, 1 on c2
			sendRandomMessages(c1, c2, 1);		
			// 5 lines of messages: 3 on e1, 2 on c2
			sendRandomEncMessages(c1, c2, 1);
			// 2 pairs of identical lines of messages: 2 on e1, 2 on c2
			sendRandomMessages(c2, c1, 2);
			// ERROR
			sendRandomMessages(c2, c2, 1);	
			System.out.println("===================\n");
			
			System.out.println("e2 eavesdrops on c2");
			System.out.println("===================");
			e2.eavesdrop(c2.getName());
			System.out.println("===================\n");

			System.out.println("e2 eavesdrops on e2");
			System.out.println("===================");
			// ERROR
			e2.eavesdrop(e2.getName());
			System.out.println("===================\n");
			
			System.out.println("Sending Messages");
			System.out.println("===================");
			// 3 identical lines of messgaes: 1 on e1, 1 on e2, 1 on c2
			sendRandomMessages(c1, c2, 1);
			// 4 lines of messages: 1 on e1, 1 on e2, 2 on c2
			sendRandomEncMessages(c1, c2, 1);
			// 2 triples of identical lines of messages: 2 on e1, 2 on e2, 2 on c1
			sendRandomMessages(c2, c1, 2);
			// 1 line of messages: 1 on e2
			sendRandomMessages(e1, e2, 1);
			// 1 line of messages: 1 on e1
			sendRandomMessages(e2, e1, 1);
			System.out.println("===================\n");

			// =========================================			
			// TEST2
			// =========================================
			System.out.println("Unregistering Clients");
			System.out.println("===================");
			server.unregisterClient(c1.getName());
			System.out.println("===================\n");
				
			System.out.println("Sending Messages");
			System.out.println("===================");
			// ERROR
			sendRandomMessages(c1, c2, 1);		
			// ERROR
			sendRandomMessages(c2, c1, 1);
			// 2 pairs of identical lines of messages: 2 on e2, 2 on c2
			sendRandomMessages(e1, c2, 2);
			System.out.println("===================\n");
			
			System.out.println("e2 stops eavesdropping on c2");
			System.out.println("===================");
			e2.stopEavesdrop(c2.getName());
			System.out.println("===================\n");
			
			System.out.println("Sending Messages");
			System.out.println("===================");
			// ERROR
			sendRandomMessages(e1, c1, 1);	
			// 2 messages: 2 on c2
			sendRandomMessages(e1, c2, 2);
			// ERROR
			sendRandomEncMessages(e1, e1, 1);	
			System.out.println("===================\n");
			
			// =========================================			
			// TEST3
			// =========================================
			System.out.println("Getting c1's messages");
			System.out.println("===================");
			// 5 messages
			// c2 to c1: 5 (4 decrypted, 0 encrypted, 1 key)
			System.out.println(c1.getMessages());
			System.out.println("===================\n");

			System.out.println("Getting c2's messages");
			System.out.println("===================");
			// 9 messages
			// c1 to c2: 5 (2 decrypted, 2 encrypted, 1 key)
			// e1 to c2: 4 (4 decrypted, 0 encrypted, 0 keys)
			System.out.println(c2.getMessages());
			System.out.println("===================\n");
			
			System.out.println("Getting e1's messages");
			System.out.println("===================");
			// 11 messages
			// c1 to c2: 5 (2 decrypted, 2 encrypted, 1 key)
			// c2 to c1: 5 (4 decrypted, 0 encrypted, 1 key)
			// e2 to e1: 1 (1 decrypted, 0 encrypted, 0 keys)
			System.out.println(e1.getMessages());
			System.out.println("===================\n");
			
			System.out.println("Getting e2's messages");
			System.out.println("===================");
			// 7 messages
			// c1 to c2: 2 (1 decrypted, 1 encrypted, 0 keys)
			// c2 to c1: 2 (2 dectypted, 0 encrypted, 0 keys)
			// e1 to c2: 2 (2 decrypted, 0 encrypted, 0 keys)
			// e2 to e1: 1 (1 decrypted, 0 encrypted, 0 keys)
			System.out.println(e2.getMessages());
			System.out.println("===================\n");
						
			System.exit(0);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
