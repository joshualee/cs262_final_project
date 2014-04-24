package edu.harvard.cs262.tests;

import java.net.InetAddress;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.util.UUID;

import edu.harvard.cs262.crypto.CentralServer;
import edu.harvard.cs262.crypto.ClientNotFound;
import edu.harvard.cs262.crypto.CryptoClient;
import edu.harvard.cs262.crypto.CryptoMessage;
import edu.harvard.cs262.crypto.CryptoServer;
import edu.harvard.cs262.crypto.DHCryptoClient;

/**
 * 
 * @author joshualee
 *
 */

public class CryptoCommuncationTest {
	
	private static String rmiHost;
	private final static int rmiPort = 8080;
	private final static String serverName = "server";
	
	private static void setupServer() throws RemoteException {
		CentralServer server = new CentralServer(serverName);
		CryptoServer serverStub = (CryptoServer) UnicastRemoteObject
				.exportObject(server, 0);

		// create registry so we don't have to manually start
		// the registry server elsewhere
		Registry registry = LocateRegistry.createRegistry(rmiPort);
		
		// rebind to avoid AlreadyBoundException
		registry.rebind(serverName, serverStub);
	}
	
	private static CryptoClient createClient(String name, CryptoServer server) throws RemoteException {
		CryptoClient myClient = new DHCryptoClient(name, server);
		CryptoClient myClientSer = ((CryptoClient)
	    		  UnicastRemoteObject.exportObject(myClient, 0));
		
		server.registerClient(myClientSer);
		return myClient;
	}
	
	private static void sendRandomMessages(CryptoClient c1, CryptoClient c2, int numMessages) throws RemoteException, ClientNotFound, InterruptedException {
		for (int i = 0; i < numMessages; i++) {
			String uuid1 = UUID.randomUUID().toString();
			String uuid2 = UUID.randomUUID().toString();
			c1.sendMessage(c2.getName(), uuid1, "");
			c2.sendMessage(c1.getName(), uuid2, "");
		}
	}
	
	private static void sendRandomEncMessages(CryptoClient c1, CryptoClient c2, int numMessages) throws RemoteException, ClientNotFound, InterruptedException {
		for (int i = 0; i < numMessages; i++) {
			String uuid1 = UUID.randomUUID().toString();
			String uuid2 = UUID.randomUUID().toString();
			c1.sendEncryptedMessage(c2.getName(), uuid1, "");
//			c2.sendEncryptedMessage(c1.getName(), uuid2, "");
		}
	}
	
	public static void main(String args[]) {		
		try {
			rmiHost = InetAddress.getLocalHost().getHostAddress();
			System.setProperty("java.security.policy", "all.policy");
			
			if (System.getSecurityManager() == null) {
				System.setSecurityManager(new SecurityManager());
			}
			
			setupServer();
			Registry registry = LocateRegistry.getRegistry(rmiHost, rmiPort);
			CryptoServer server = (CryptoServer) registry.lookup(serverName);
			
			CryptoClient c1 = createClient("c1", server);
			CryptoClient c2 = createClient("c2", server);
			CryptoClient e1 = createClient("e1", server);
			
			e1.eavesdrop("c1");
			e1.eavesdrop("c2");
			
			sendRandomEncMessages(c1, c2, 1);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
