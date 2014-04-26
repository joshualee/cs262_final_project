package edu.harvard.cs262.crypto;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.util.Scanner;

public class EVoteClient {
	public static void main(String args[]) {
		if (args.length != 3) {
			System.err.println("usage: java DHCryptoClient rmiHost rmiPort serverName");
			System.exit(1);
		}
		
		// args[0]: IP (registry)
		// args[1]: Port (registry)
		// args[2]: Server name
		
		String rmiHost = args[0];
		int rmiPort = Integer.parseInt(args[1]);
		String serverName = args[2];
		
		if (System.getSecurityManager() == null) {
			System.setSecurityManager(new SecurityManager());
		}
		
		try {
			Scanner scan = new Scanner(System.in);
			Registry registry = LocateRegistry.getRegistry(rmiHost, rmiPort);
			CryptoServer server = (CryptoServer) registry.lookup(serverName);
		
			System.out.print("Enter your name: ");
			String clientName = scan.nextLine();
			
			CryptoClient myClient = new DHCryptoClient(clientName, server);
			CryptoClient myClientSer = ((CryptoClient)UnicastRemoteObject.exportObject(myClient, 0));
			
			server.registerClient(myClientSer);
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}
}
