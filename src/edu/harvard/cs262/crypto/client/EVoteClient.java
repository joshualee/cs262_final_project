package edu.harvard.cs262.crypto.client;

import java.math.BigInteger;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.util.Random;
import java.util.Scanner;

import edu.harvard.cs262.crypto.CryptoMessage;
import edu.harvard.cs262.crypto.EVote;
import edu.harvard.cs262.crypto.VPrint;
import edu.harvard.cs262.crypto.cipher.CryptoKey;
import edu.harvard.cs262.crypto.cipher.DHTuple;
import edu.harvard.cs262.crypto.cipher.ElGamalCipher;
import edu.harvard.cs262.crypto.exception.ClientNotFound;
import edu.harvard.cs262.crypto.exception.EVoteInvalidResult;
import edu.harvard.cs262.crypto.server.CryptoServer;

public class EVoteClient extends DHCryptoClient {
	
	public EVoteClient(String name, CryptoServer server) {
		super(name, server);
	}
	
	// does this need to throw ClientNotFound?	
	public void eVote(EVote evote) throws RemoteException, ClientNotFound, InterruptedException {
		Random rand = new Random(262);
		String sid = evote.id.toString();
		
		/*
		 * EVote phase one: 
		 * client receives a ballot from the server
		 */
		log.print(VPrint.QUIET, "initiating e-vote...");
		log.print(VPrint.QUIET, "ballot %s: %s", sid, evote.ballot);
		
		int yay_or_nay;
//		int yay_or_nay = rand.nextInt(2);
		String clientVote = "";
		
		log.print(VPrint.QUIET, "y: vote in favor");
		log.print(VPrint.QUIET, "n: vote against");
		log.print(VPrint.QUIET, "vote [y\\n]: ");
		
		Scanner scan = new Scanner(System.in);
		
		while (true) {
			clientVote = scan.nextLine();
			if (clientVote.equals("y")) {
				log.print(VPrint.LOUD, "you voted in favor ballot %s", sid);
				yay_or_nay = 1;
				break;
			}
			else if (clientVote.equals("n")) {
				log.print(VPrint.LOUD, "you voted in against ballot %s", sid);
				yay_or_nay = 0;
				break;
			}
			else {
				log.print(VPrint.QUIET, "try again [y\\n]: ");
			}
		}
		
		scan.close();
		
		log.print(VPrint.QUIET, "tallying vote...");
		
		
		/*
		 * EVote phase two: 
		 * each client generates own secret key and sends to server
		 */
		BigInteger sk_i = (new BigInteger(evote.BITS, rand)).mod(evote.p);
		BigInteger pk_i = evote.g.modPow(sk_i, evote.p);
		
		
		log.print(VPrint.DEBUG, "g=%s, p=%s", evote.g, evote.p);
		log.print(VPrint.DEBUG, "sk_i=%s, pk_i=%s", sk_i, pk_i);
		
		CryptoMessage phaseTwo = new CryptoMessage(pk_i.toString(), sid);
		server.recvMessage(getName(), server.getName(), phaseTwo);
		CryptoMessage pkMsg = waitForMessage(sid);
		
		/*
		 * EVote phase four:
		 * client decides vote and encrypts using ElGamal 
		 */
		
		// since for now we only do the encryption phase,
		// we only have to set the public key
		ElGamalCipher EGCipher = new ElGamalCipher();
		DHTuple	dht = new DHTuple(evote.p, evote.g, 
				new BigInteger(pkMsg.getPlainText()));

		CryptoKey publicKey = new CryptoKey(null, dht, evote.BITS);
		EGCipher.setKey(publicKey);
		
		// TODO: vote input instead of random
		BigInteger vote = evote.g.pow(yay_or_nay).mod(evote.p);
		// TODO: encrypt vote directly since it is already a number... instead of
		// doing the string manipulation
		CryptoMessage encryptedVote = EGCipher.encryptInteger(vote);
		encryptedVote.setSessionID(sid);
		
		// TODO: send tag with server message, so clients know what they are seeing when eaves dropping
		// TODO: store server name
		server.recvMessage(name, server.getName(), encryptedVote);
		
		/*
		 * EVote phase 6:
		 * receive combined cipher text from server
		 * let (c1, c2) = cipher text
		 * compute (c1)^(sk_i) and send to server
		 */
		
		CryptoMessage combinedCipher = waitForMessage(sid);
		BigInteger c1 = (BigInteger) combinedCipher.getEncryptionState();
		BigInteger c2 = new BigInteger(combinedCipher.getPlainText());
		BigInteger encryptedC1 = c1.modPow(sk_i, evote.p);
		
		server.recvMessage(name, server.getName(), 
				new CryptoMessage(encryptedC1.toString(), sid));
		/*
		 * EVote phase 8:
		 * clients use decodingKey to decode message 
		 */
		int numYays, numNays;
		int numVoters = evote.voters.size();
		
		CryptoMessage decodingKeyMsg = waitForMessage(sid);
		BigInteger decodingKey = new BigInteger(decodingKeyMsg.getPlainText());
		BigInteger voteResult = c2.multiply(decodingKey.modInverse(evote.p)).mod(evote.p);
		
		try {
			numYays = evote.countYays(voteResult, numVoters);
			numNays = numVoters - numYays;
		} catch (EVoteInvalidResult e) {
			log.print(VPrint.ERROR, "evote failed: %s", e.getMessage());
			return;
		}
		
		log.print(VPrint.DEBUG, "raw vote result: %s", voteResult.toString());
		
		log.print(VPrint.QUIET, "ballot %s vote results: %d voted yes, %d voted no", sid, numYays, numNays);

		if (numYays > numNays) {
			log.print(VPrint.QUIET, "ballot %s has passed", sid);
		}
		else {
			log.print(VPrint.QUIET, "ballot %s has NOT passed", sid);
		}
	}

	public static void main(String args[]) {
		Scanner scan;
		
		if (args.length != 3) {
			System.err.println("usage: java DHCryptoClient rmiHost rmiPort serverName");
			System.exit(1);
		}
		
		
		String rmiHost = args[0];
		int rmiPort = Integer.parseInt(args[1]);
		String serverName = args[2];
		
		if (System.getSecurityManager() == null) {
			System.setSecurityManager(new SecurityManager());
		}
		
		try {
			scan = new Scanner(System.in);
			Registry registry = LocateRegistry.getRegistry(rmiHost, rmiPort);
			CryptoServer server = (CryptoServer) registry.lookup(serverName);
		
			System.out.print("Enter your name: ");
			String clientName = scan.nextLine();
			
			CryptoClient myClient = new EVoteClient(clientName, server);
			CryptoClient myClientSer = ((CryptoClient)UnicastRemoteObject.exportObject(myClient, 0));
			
			server.registerClient(myClientSer);
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}
}