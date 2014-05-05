package edu.harvard.cs262.crypto.client;

import java.math.BigInteger;
import java.rmi.ConnectException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.util.Random;
import java.util.Scanner;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import edu.harvard.cs262.crypto.CryptoMessage;
import edu.harvard.cs262.crypto.EVote;
import edu.harvard.cs262.crypto.Helpers;
import edu.harvard.cs262.crypto.VPrint;
import edu.harvard.cs262.crypto.cipher.CryptoKey;
import edu.harvard.cs262.crypto.cipher.DHTuple;
import edu.harvard.cs262.crypto.cipher.ElGamalCipher;
import edu.harvard.cs262.crypto.exception.ClientNotFound;
import edu.harvard.cs262.crypto.exception.EVoteInvalidResult;
import edu.harvard.cs262.crypto.server.CryptoServer;

/**
 * A CryptoClient that uses DiffieHellman key exchange and ElGamal encryption.
 * This client also supports e-voting. 
 *
 * @author Joshua Lee and Tracy Lu 
 */

public class EVoteClient extends DHCryptoClient {	
	private Object currentVoteLock;
	private Future<Object> currentVote;
	private Scanner userInput;
	private Integer testVote;
	
	public EVoteClient(String name, CryptoServer server) {
		super(name, server);
		currentVoteLock = new Object();
		currentVote = null;
		userInput = Helpers.nonClosingScanner(System.in);
		setTestVote(null);
	}
	
	/**
	 * Perform the evote
	 * @param evote
	 * 		The evote to be done
	 * @throws RemoteException
	 * @throws ClientNotFound
	 */
	private void doEvote(EVote evote) throws RemoteException, ClientNotFound {
		
		try {
			long seed = (int) (Math.random() * 1000);
			Random rand = new Random(seed);
			String sid = evote.id.toString();
			String serverName = server.getName();
			
			/**
			 * EVote phase one: 
			 * client receives a ballot from the server
			 */
			log.print(VPrint.QUIET, "initiating e-vote...");
			log.print(VPrint.QUIET, "ballot %s", sid);
			log.print(VPrint.QUIET, "--------------------------------------");
			log.print(VPrint.QUIET, "proposal: %s", evote.ballot);
			
			int yay_or_nay = 0;
			String clientVote = "";
			
			log.print(VPrint.QUIET, "y: vote in favor");
			log.print(VPrint.QUIET, "n: vote against");
			log.print(VPrint.QUIET, "vote [y\\n]: ");
			
			// only accept input when not testing
			if (testVote != null) {
				yay_or_nay = testVote.intValue();
				
				// this simulates a nonresponsive client
				// for now we simulate failing whenever we are in test mode and
				// we supply an invalid vote
				if (yay_or_nay != 0 && yay_or_nay != 1) {
					while (true) { }
				}
			}
			
			while (testVote == null) {
				while (!Helpers.concurrentHasNextLine(userInput)) {
					try {
						Thread.sleep(1000);
					} catch (InterruptedException e) {
						log.print(VPrint.DEBUG, "scanner interrupted");
						throw e;
					}					
				}
				
				if (Thread.currentThread().isInterrupted()) {
					throw new InterruptedException();
				}
				
				clientVote = userInput.nextLine();
				if (clientVote.equals("y")) {
					log.print(VPrint.QUIET, "you voted in favor of ballot %s", sid);
					yay_or_nay = 1;
					break;
				}
				else if (clientVote.equals("n")) {
					log.print(VPrint.QUIET, "you voted against ballot %s", sid);
					yay_or_nay = 0;
					break;
				}
				else {
					log.print(VPrint.QUIET, "try again [y\\n]: ");
				}
			}
			
			log.print(VPrint.QUIET, "tallying vote...");
			
			/**
			 * EVote phase two: 
			 * each client generates own secret key and sends to server
			 */
			BigInteger sk_i = (new BigInteger(evote.BITS, rand)).mod(evote.p);
			BigInteger pk_i = evote.g.modPow(sk_i, evote.p);
			
			log.print(VPrint.DEBUG, "g=%s, p=%s", evote.g, evote.p);
			log.print(VPrint.DEBUG, "sk_i=%s, pk_i=%s", sk_i, pk_i);
			
			CryptoMessage phaseTwo = new CryptoMessage(pk_i.toString(), sid);
			phaseTwo.setTag("secret key partition");
			server.recvMessage(getName(), serverName, phaseTwo);
			CryptoMessage pkMsg = waitForMessage(sid);
			
			/**
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
			
			BigInteger vote = evote.g.pow(yay_or_nay).mod(evote.p);
			CryptoMessage encryptedVote = EGCipher.encryptInteger(vote);
			encryptedVote.setSessionID(sid);
			
			encryptedVote.setTag("encrypted vote");
			server.recvMessage(name, serverName, encryptedVote);
			
			/**
			 * EVote phase 6:
			 * receive combined cipher text from server
			 * let (c1, c2) = cipher text
			 * compute (c1)^(sk_i) and send to server
			 */
			
			CryptoMessage combinedCipher = waitForMessage(sid);
			BigInteger c1 = (BigInteger) combinedCipher.getEncryptionState();
			BigInteger c2 = new BigInteger(combinedCipher.getPlainText());
			BigInteger encryptedC1 = c1.modPow(sk_i, evote.p);
			
			CryptoMessage decryptKeyPart = new CryptoMessage(encryptedC1.toString(), sid);
			decryptKeyPart.setTag("decryption key partition");
			server.recvMessage(name, serverName, decryptKeyPart);
			
			/**
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
			
			log.print(VPrint.QUIET, "ballot %s vote results", sid);
			log.print(VPrint.QUIET, "---------------------------------------------------------");
			log.print(VPrint.QUIET, "in favor: %s", numYays);
			log.print(VPrint.QUIET, "against: %s", numNays);
			
			if (numYays > numNays) {
				log.print(VPrint.QUIET, "[PASSED] ballot %s", sid);
			}
			else {
				log.print(VPrint.QUIET, "[REJECTED] ballot %s", sid);
			}
		} catch (InterruptedException e) {
			log.print(VPrint.DEBUG, "evoting thread closed due to interuption: %s", e.getMessage());
		}
	}
	
	private class evoteCallable implements Callable<Object> {
		private EVote evote;
		
		public evoteCallable(EVote evote) {
			this.evote = evote;
		}
		
		@Override
		public Object call() {
			try {
				doEvote(evote);
			} catch (Exception e) {
				log.print(VPrint.ERROR, e.getMessage());
			}
			
			return null;
		}
		
	}
	
	@Override
	public void evoteAbort(String abortMessage) throws RemoteException {
		log.print(VPrint.DEBUG, "evoteAbort(%s)", abortMessage);
		
		synchronized (currentVoteLock) {
			if (currentVote == null) {
				log.print(VPrint.WARN, "asked to abort vote, but not currently voting");
			}
			else {
				log.print(VPrint.ERROR, "aborting evote: %s", abortMessage);
				
				boolean cancelled = currentVote.cancel(true);
				if (cancelled) {
					log.print(VPrint.DEBUG, "vote successfully cancelled");
				} else {
					log.print(VPrint.DEBUG, "vote not cancelled");
				}
				
				currentVote = null;
			}
		}
	}
	
	public void evote(EVote evote) throws RemoteException, ClientNotFound, InterruptedException, EVoteInvalidResult {
		Future<Object> evoteFuture;
		
		synchronized (currentVoteLock) {
			if (currentVote != null) {
				String error = String.format("%s already participating in evote", name);
				log.print(VPrint.ERROR, error);
				throw new EVoteInvalidResult(error);
			}
			else {				
				ExecutorService pool = Executors.newSingleThreadExecutor();
				evoteCallable evoteCall = new evoteCallable(evote);
				evoteFuture = pool.submit(evoteCall);
				currentVote = evoteFuture;
			}
		}
		
		while (!evoteFuture.isDone()) {
			// block until the vote finishes or throws an error
		}
		
		try {
			evoteFuture.get();
		} catch (ExecutionException e) {
			String msg = e.getCause().getMessage();
			String msg2 = e.getMessage();
			synchronized (currentVoteLock) {
				currentVote = null;
			}
			log.print(VPrint.ERROR, "evote failed: %s", msg2);
			throw new EVoteInvalidResult(msg); 
		} catch (InterruptedException e) {
			log.print(VPrint.ERROR, "interupted...");
		}
		
		synchronized (currentVoteLock) {
			currentVote = null;
		}
				
	}

	public static void main(String args[]) {
		Scanner scan;
		
		if (args.length != 3) {
			System.err.println("usage: java EVoteClient rmiHost rmiPort serverName");
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
			scan = new Scanner(System.in);
			Registry registry = LocateRegistry.getRegistry(rmiHost, rmiPort);
			CryptoServer server = (CryptoServer) registry.lookup(serverName);
		 
			while(true)
			{
				while(clientName.length() == 0){
					System.out.print("Enter your name: ");
					// trim trailing and leading whitespace from name
					clientName = scan.nextLine().trim();
				}
			
				CryptoClient myClient = new EVoteClient(clientName, server);
				CryptoClient myClientSer = ((CryptoClient)UnicastRemoteObject.exportObject(myClient, 0));
				
				if (server.registerClient(myClientSer)) {
					System.out.println(String.format("Hello, %s. You have successfully registered with server: %s", clientName, serverName));
					System.out.println(String.format("Please wait. Server will initiate evotes soon..."));
					break;
				} 
				else {
					System.out.println("Client with name " + clientName + " already exists.");
					clientName="";
				}
			}	
		}
		catch (ConnectException e) {
			System.out.println("Failed to find RMI registery. Either the server hasn't started yet, you have the wrong host/port, or you have a firewall issue...");
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	public Integer getTestVote() {
		return testVote;
	}

	public void setTestVote(Integer testVote) {
		this.testVote = testVote;
	}
}
