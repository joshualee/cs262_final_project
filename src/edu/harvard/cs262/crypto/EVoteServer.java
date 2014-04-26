package edu.harvard.cs262.crypto;

import java.net.InetAddress;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.util.Scanner;

public class EVoteServer {
	
	public static void main(String args[]) {
		if (args.length != 2) {
			System.err.println("usage: java EVoteServer rmiport servername");
			System.exit(1);
		}
		
		try {
			if (System.getSecurityManager() == null) {
				System.setSecurityManager(new SecurityManager());
			}
			
			String rmiHost = InetAddress.getLocalHost().getHostAddress();
			int registryPort = Integer.parseInt(args[0]);
			String serverName = args[1];
			
			CentralServer server = new CentralServer(serverName);
			CryptoServer serverStub = (CryptoServer) UnicastRemoteObject
					.exportObject(server, 0);

			// create registry so we don't have to manually start
			// the registry server elsewhere
			Registry registry = LocateRegistry.createRegistry(registryPort);
			
			registry.rebind(serverName, serverStub); 
			System.out.println("Running EVote server '' at %s:%s");
			System.out.println("Waiting for client connections...");
			
			/*
			 * Prompt user for ballot
			 */
			Scanner scan = new Scanner(System.in);
			
			while (true) {
				System.out.println("Enter ballot:");
				String ballot = scan.nextLine();
				server.initiateEVote(ballot);
			}

		} catch (Exception e) {
			System.err.println("Server exception: " + e.toString());
		}
		
	}

}
