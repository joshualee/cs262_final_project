package edu.harvard.cs262.crypto.client;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import edu.harvard.cs262.crypto.CryptoMessage;
import edu.harvard.cs262.crypto.server.CryptoServer;

public class ClientConsole {
	
	public static void main(String args[]) {
		Scanner scan;
		
		if (args.length != 3) {
			System.err.println("usage: java ClientConsole rmiHost rmiPort serverName");
			System.exit(1);
		}

		String rmiHost = args[0];
		int rmiPort = Integer.parseInt(args[1]);
		String serverName = args[2];

		if (System.getSecurityManager() == null) {
			System.setSecurityManager(new SecurityManager());
		}

		try {
			String clientName = "";
			CryptoClient myClient = null;
			Registry registry = LocateRegistry.getRegistry(rmiHost, rmiPort);
			CryptoServer server = (CryptoServer) registry.lookup(serverName);

			// Create new Scanner
			scan = new Scanner(System.in);

			// boolean to keep track of whether the Client is registered
			boolean reg = false;

			// Menu
			String menu = 
				"\n====== Help Menu ======\n" +
			    "u: unregister\n" +
			    "c: see list of registered clients\n" +
				"m: send message to client\n" +
				"e: listen to a client's communications\n" +
				"s: stop listening to a client's communications\n" +
				"r: see list of all received messages\n" +
				"q: quit\n" +
				"h: display this menu";
			String s = "";

			while (true) {

				// make client register before it can do anything else
				while (!reg) {

					while(clientName.length() == 0){
						System.out.print("Enter your name: ");
						// trim trailing and leading whitespace from name
						clientName = scan.nextLine().trim();
					}
					
					myClient = new DHCryptoClient(clientName, server);
					CryptoClient myClientSer = ((CryptoClient) UnicastRemoteObject.exportObject(myClient, 0));

					if (server.registerClient(myClientSer)) {
						System.out.println(menu);
						System.out.println("\nWelcome, " + clientName + ". Please choose an action.");
						reg = true;
						break;
					}
					System.out.println("Client with name " + clientName + " already exists.");
					clientName="";
				}

				while (reg) {
					System.out.print("\n>> ");
					s = scan.nextLine();

					// unregsiter client
					if (s.equals("u")) {
						if (server.unregisterClient(clientName)) {
							System.out.println("You have successfully been unregistered.");
							clientName = "";
							reg = false;
							break;
						}

						// note: this case *shouldn't* happen
						else {
							System.out.println("Error: you are not registered");
						}
					}

					// show list of registered clients
					else if (s.equals("c")) {
						System.out.println("\n" + server.getClientList(false));
					}

					// send message to client
					else if (s.equals("m")) {
						String encr = "";

						System.out.print("To: ");
						String to = scan.nextLine();
						System.out.print("Message: ");
						String msg = scan.nextLine();

						while (!encr.equals("y") && !encr.equals("n")) {
							System.out.print("Would you like to encrypt this message (y/n)? ");
							encr = scan.nextLine();
						}
						
						if (encr.equals("y")) {
							myClient.sendEncryptedMessage(to, msg, "");
						}

						else {
							myClient.sendMessage(to, msg, "");
						}
					}

					// listen to a client's communications
					else if (s.equals("e")) {
						System.out.print("Eavesdrop on: ");
						String vic = scan.nextLine();
						myClient.eavesdrop(vic);
					}

					// stop listening to a client's communications
					else if (s.equals("s")) {
						System.out.print("Stop eavesdropping on: ");
						String vic = scan.nextLine();
						myClient.stopEavesdrop(vic);
					}

					// see list of all received messages
					else if (s.equals("r")) {
						Map<ClientPair, List<CryptoMessage>> messageMap = myClient.getMessages();

						if (!messageMap.isEmpty()) {

							for (Map.Entry<ClientPair, List<CryptoMessage>> entry : messageMap
									.entrySet()) {
								// print "From: ..., To: ..."
								ClientPair myPair = entry.getKey();
								System.out.println("\n" + myPair + "\n=================");
								List<CryptoMessage> messageList = entry.getValue();

								for (CryptoMessage m : messageList) {
									// output decrypted version only if myClient
									// was intended target or message wasn't encrypted
									String dec = "\nDecrypted: ";
									if (myPair.getTo().equals(myClient.getName()) || !m.isEncrypted()) {
										dec += m.getPlainText();
									}
									else
									{
										dec += "N/A";
									}
									System.out.println(dec);
									
									// output encrypted version if message was encrypted
									if (m.isEncrypted()){ 
										System.out.println("Encrypted: " + m.getCipherText());
									}
								}
							}
						} else {
							System.out.println("You have not received or eavesdropped on any messages.");
						}
					}

					// print help menu
					else if (s.equals("h")) {
						System.out.println(menu);
					}
					
					// quit system
					else if (s.equals("q")) {
						System.exit(0);
					}
					
					// other
					else {
						System.out.println("Unrecognized command.");
					}
				}
				
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
