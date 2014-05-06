package edu.harvard.cs262.tests;

import java.math.BigInteger;
import java.net.InetAddress;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.util.Random;
import java.util.UUID;

import edu.harvard.cs262.crypto.CryptoMessage;
import edu.harvard.cs262.crypto.cipher.CryptoKey;
import edu.harvard.cs262.crypto.cipher.DHTuple;
import edu.harvard.cs262.crypto.cipher.ElGamalCipher;
import edu.harvard.cs262.crypto.client.CryptoClient;
import edu.harvard.cs262.crypto.client.EVoteClient;
import edu.harvard.cs262.crypto.exception.ClientNotFound;
import edu.harvard.cs262.crypto.server.CentralServer;
import edu.harvard.cs262.crypto.server.CryptoServer;
import edu.harvard.cs262.crypto.server.EVoteServer;

/**
 * Sandbox for testing client server interaction.
 * 
 * @author Holly Anderson, Joshua Lee, and Tracy Lu
 *
 */
public class CryptoSandbox {
	
	private static String rmiHost;
	private final static int rmiPort = 8082;
	private final static String serverName = "testserver";
	
	private static void setupServer() throws RemoteException {
		CentralServer server = new EVoteServer(serverName);
		CryptoServer serverStub = (CryptoServer) UnicastRemoteObject
				.exportObject(server, 0);

		// create registry so we don't have to manually start
		// the registry server elsewhere
		Registry registry = LocateRegistry.createRegistry(rmiPort);
		
		// rebind to avoid AlreadyBoundException
		registry.rebind(serverName, serverStub);
	}
	
	private static CryptoClient createClient(String name, CryptoServer server) throws RemoteException {
		CryptoClient myClient = new EVoteClient(name, server);
		CryptoClient myClientSer = ((CryptoClient)
	    		  UnicastRemoteObject.exportObject(myClient, 0));
		
		server.registerClient(myClientSer);
		return myClient;
	}
	
	@SuppressWarnings("unused")
	private static void sendRandomMessages(CryptoClient c1, CryptoClient c2, int numMessages) throws RemoteException, ClientNotFound, InterruptedException {
		for (int i = 0; i < numMessages; i++) {
			String uuid1 = UUID.randomUUID().toString();
			String uuid2 = UUID.randomUUID().toString();
			c1.sendMessage(c2.getName(), uuid1, "");
			c2.sendMessage(c1.getName(), uuid2, "");
		}
	}
	
	@SuppressWarnings("unused")
	private static void sendRandomEncMessages(CryptoClient c1, CryptoClient c2, int numMessages) throws RemoteException, ClientNotFound, InterruptedException {
		for (int i = 0; i < numMessages; i++) {
			String uuid1 = UUID.randomUUID().toString();
			String uuid2 = UUID.randomUUID().toString();
			c1.sendEncryptedMessage(c2.getName(), uuid1, "");
//			c2.sendEncryptedMessage(c1.getName(), uuid2, "");
		}
	}
	
	@SuppressWarnings("unused")
	private static void testElGamal() {
		BigInteger test = new BigInteger("2134");
		BigInteger P = BigInteger.valueOf(31123L);
		BigInteger G = BigInteger.valueOf(2341L);
		int bits = 31;
		
		Random rand = new Random(262);
		
		BigInteger x = new BigInteger(bits, rand);
		BigInteger x_hat = G.modPow(x, P);
		
		DHTuple publicKey = new DHTuple(P, G, x_hat);
		
		CryptoKey ck = new CryptoKey(x, publicKey, bits);
		
		ElGamalCipher eg = new ElGamalCipher();
		eg.setKey(ck);
		
//		CryptoMessage encrypted = eg.encrypt(test.toString());
		CryptoMessage encrypted = eg.encryptInteger(test);
		String decrypted = eg.decryptInteger(encrypted);
		if (decrypted.equals(test.toString())) {
			System.out.println("ElGamal success!");
		}
		else {
			System.out.println(String.format("ElGamal failure (%s, %s)", test, decrypted));
		}
		
	}

	@SuppressWarnings("unused")
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
			
			CryptoClient c1 = createClient("c1", server);
			CryptoClient c2 = createClient("c2", server);
			CryptoClient e1 = createClient("e1", server);
//			CryptoClient c3 = createClient("c3", server);
//			CryptoClient c4 = createClient("c4", server);
//			CryptoClient c5 = createClient("c5", server);
//			CryptoClient c6 = createClient("c6", server);
//			CryptoClient c7 = createClient("c7", server);
//			CryptoClient c8 = createClient("c8", server);
//			CryptoClient c9 = createClient("c9", server);
			
//			Thread.sleep(1000);
			server.initiateEVote("test ballot josh");
//			testElGamal();
			
//			e1.eavesdrop("c1");
//			e1.eavesdrop("c2");
			
//			sendRandomEncMessages(c1, c2, 1);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
