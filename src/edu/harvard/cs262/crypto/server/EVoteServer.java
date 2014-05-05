package edu.harvard.cs262.crypto.server;

import java.math.BigInteger;
import java.net.InetAddress;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Scanner;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import edu.harvard.cs262.crypto.CryptoMessage;
import edu.harvard.cs262.crypto.EVote;
import edu.harvard.cs262.crypto.VPrint;
import edu.harvard.cs262.crypto.client.CryptoClient;
import edu.harvard.cs262.crypto.exception.ClientNotFound;
import edu.harvard.cs262.crypto.exception.EVoteInvalidResult;

/**
 * A server that handles e-voting by using the send/receive message protocols of CentralServer
 *
 * @author Holly Anderson, Joshua Lee, and Tracy Lu
 */
public class EVoteServer extends CentralServer {
	private static int EVOTETIMEOUT = 120; // in seconds 
	private Set<String> currentVotingClients;
	protected Map<String, Map<String, CryptoMessage>> sessions;
	
	public EVoteServer(String name) {
		super(name);
		sessions = new ConcurrentHashMap<String, Map<String, CryptoMessage>>();
		currentVotingClients = new HashSet<String>();
	}
	
	/** Handles when a client fails or unregisters */
	public boolean unregisterClient(String clientName) throws RemoteException {
		
		synchronized (currentVotingClients) {
			if (currentVotingClients.contains(clientName)) {
				String msg = String.format("aborting vote because %s unregistered midvote", clientName);
				/**
				 * Because we don't have a reference to the server thread doing the vote here
				 * we don't cancel it. In the future, we can make the server thread into
				 * an instance variable so we have a reference.
				 */
				abortEVote(msg, null, currentVotingClients);
			}
		}
		
		return super.unregisterClient(clientName);
	}
		
	/**
	 * Blocks until all registered clients have sent a message with sid 
	 * @param sid the session id to wait on
	 * @throws InterruptedException 
	 */
	public Map<String, CryptoMessage> waitForAll(Set<String> clientList, String sid) throws InterruptedException {
		Map<String, CryptoMessage> clientMap;
		
		synchronized (sessions) {
			while (!sessions.containsKey(sid)) {
				sessions.wait();
			}
			
			clientMap = sessions.get(sid);
		}
		
		synchronized (clientMap) {
			for (String client : clients.keySet()) {
				while (!clientMap.containsKey(client)) {
					clientMap.wait();
				}
			}
			
			clientMap = sessions.remove(sid);
			clientMap.notifyAll();
		}
		
		return clientMap;
	}
	
	/**
	 * Waits for message from a particular session ID
	 * @param from: the client sending the message
	 * @param sid: the session id to wait on
	 * @throws InterruptedException 
	 */
	public CryptoMessage waitForMessage(String from, String sid) throws InterruptedException {
		Map<String, CryptoMessage> clientMap;
		CryptoMessage m;
		
		synchronized (sessions) {
			while (!sessions.containsKey(sid)) {
				sessions.wait();
			}
			
			clientMap = sessions.get(sid);
		
			while (!clientMap.containsKey(from)) {
				clientMap.wait();
			}
			
			m = clientMap.remove(from);
			sessions.notifyAll();
		}
		
		return m;
	}
	
	/** Handles messages sent from clients to the server */
	public String recvMessage(String from, String to, CryptoMessage m) throws RemoteException, ClientNotFound, InterruptedException {
		Map<String, CryptoMessage> sessionMap;
		
		/** Relay message to all other voting clients */	
		CryptoMessage relayMessage = new CryptoMessage(m.getPlainText(), m.getCipherText(), "");
		relayMessage.setTag(m.getTag());
		
		synchronized (currentVotingClients) {
			for (String clientName : currentVotingClients) {
				if (!clientName.equals(from)) {
					getClient(clientName).recvMessage(from, "voters", relayMessage);	
				}
			}
		}
		
		if (m.hasSessionID()) {
			String sid = m.getSessionID();
			
			synchronized (sessions) {
				sessionMap = sessions.get(sid);
				
				if (sessionMap == null) {
					sessionMap = new Hashtable<String, CryptoMessage>();
					sessions.put(sid, sessionMap);
				}
				
				sessions.notifyAll();
			}
			
			synchronized (sessionMap) {
				while (sessionMap.containsKey(from)) {
					log.print(VPrint.WARN, "(%s, %s) already has a waiting message", sid, from);
					sessionMap.wait();
				}
				sessionMap.put(from, m);
				sessionMap.notifyAll();
			}
			
			/** Don't print message, because another thread will handle it */
			return "";
		}
		
		log.print(VPrint.QUIET, "%s: %s", from, m.getPlainText());
		return m.getPlainText();
	}
	
	/** Creates callable object for client e-voting (used for threading) */
	protected class clientEVote implements Callable<Object> {
		private CryptoClient client;
		private EVote evote;
		
		public clientEVote(CryptoClient client, EVote evote) {
			this.client = client;
			this.evote = evote;
		}
		
		public Object call() throws Exception {
			client.evote(evote);
			return null;		
		}
	}
	
	/** Sends message to all clients */
	private void broadcastMessage(Set<String> clientList, CryptoMessage m) throws RemoteException, InterruptedException, ClientNotFound {
		for (String client : clientList) {
			getClient(client).recvMessage(name, client, m);
		}
	}

	/** 
	 * Perform the evote
	 * @param evote: the evote to be done
	 * @param votingClients: all clients who are participating in the vote
	 * @return String containing the number of positive and negative votes
	 * @throws InterruptedException
	 * @throws RemoteException
	 * @throws ClientNotFound
	 */
	private String doEvote(EVote evote, Set<String> votingClients) throws InterruptedException, RemoteException, ClientNotFound {
		String sid = evote.id.toString();
		log.print(VPrint.QUIET, "initiating ballot %s with %d voters", sid, votingClients.size());
		
		/**
		 * EVote phase 3:
		 * server receives g^(sk_i) from each client and calculates shared public key
		 */
		Map<String, CryptoMessage> pkMsgs = waitForAll(votingClients, sid);
		BigInteger publicKey = BigInteger.valueOf(1L);
		for (CryptoMessage pkMsg : pkMsgs.values()) {
			BigInteger pk = new BigInteger(pkMsg.getPlainText());
			publicKey = publicKey.multiply(pk).mod(evote.p);
		}
		
		log.print(VPrint.DEBUG2, "publicKey: %s", publicKey);
		CryptoMessage publicKeyMessage = new CryptoMessage(publicKey.toString(), sid);
		
		broadcastMessage(votingClients, publicKeyMessage);
		
		/**
		 * EVote phase 4:
		 * server combines c_i from clients to form combined cipher text
		 */
		Map<String, CryptoMessage> cipherMsgs = waitForAll(votingClients, sid);
		BigInteger c1 = BigInteger.valueOf(1L);
		BigInteger c2 = BigInteger.valueOf(1L);
		for (CryptoMessage cipherMsg : cipherMsgs.values()) {
			BigInteger c1_i = (BigInteger) cipherMsg.getEncryptionState();
			BigInteger c2_i = new BigInteger(cipherMsg.getCipherText());
			c1 = c1.multiply(c1_i).mod(evote.p);
			c2 = c2.multiply(c2_i).mod(evote.p);
		}
		
		log.print(VPrint.DEBUG2, "c1: %s", c1);
		log.print(VPrint.DEBUG2, "c2: %s", c2);
		
		CryptoMessage combinedCipherMsg = new CryptoMessage(c2.toString(), sid);
		combinedCipherMsg.setEncryptionState(c1);
		
		broadcastMessage(votingClients, combinedCipherMsg);
		
		/**
		 * EVote phase 7:
		 * compute the decryption key and share with all clients
		 */
		Map<String, CryptoMessage> decryptMsgs = waitForAll(votingClients, sid);
		BigInteger decrypt = BigInteger.valueOf(1L);
		for (CryptoMessage decryptMsg : decryptMsgs.values()) {
			BigInteger decrypt_i = new BigInteger(decryptMsg.getPlainText());
			decrypt = decrypt.multiply(decrypt_i).mod(evote.p);
		}
		
		log.print(VPrint.DEBUG2, "decrypt: %s", decrypt);
		
		CryptoMessage decryptKeyMsg = new CryptoMessage(decrypt.toString(), sid);
		broadcastMessage(votingClients, decryptKeyMsg);
		
		/**
		 * EVote phase 8:
		 * decrypt vote
		 */
		int positiveVotes, negativeVotes;
		BigInteger voteResult = c2.multiply(decrypt.modInverse(evote.p)).mod(evote.p);
		int numVoters = votingClients.size();		
		
		try {
			positiveVotes = evote.countYays(voteResult, numVoters);
			negativeVotes = numVoters - positiveVotes;
		} catch (EVoteInvalidResult e) {
			log.print(VPrint.ERROR, "evote failed: %s", e.getMessage());
			return "";
		}
		
		log.print(VPrint.QUIET, "ballot %s vote results", sid);
		log.print(VPrint.QUIET, "---------------------------------------------------------");
		log.print(VPrint.QUIET, "in favor: %s", positiveVotes);
		log.print(VPrint.QUIET, "against: %s", negativeVotes);
		
		if (positiveVotes > negativeVotes) {
			log.print(VPrint.QUIET, "[PASSED] ballot %s", sid);
		}
		else {
			log.print(VPrint.QUIET, "[REJECTED] ballot %s", sid);
		}
		
		return String.format("(%s,%s)", positiveVotes, negativeVotes);
	}
	
	/** Creates callable object for server performing e-vote on all the clients (used for threading) */
	protected class serverEVote implements Callable<String> {
		private EVote evote;
		private Set<String> votingClients;
		
		public serverEVote(EVote evote, Set<String> votingClients) {
			this.evote = evote;
			this.votingClients = votingClients;
		}
		
		public String call() throws Exception {
			try {
				return doEvote(evote, votingClients);
			} catch (InterruptedException e) {
				log.print(VPrint.DEBUG2, e.getMessage());
				log.print(VPrint.ERROR, "serverEVote: %s", e.getCause().getMessage());
				// do nothing -- vote was aborted because client failed 
			}
			
			return "";		
		}
	}
	
	/** Begins an evote by telling all clients what the ballot is */
	public String initiateEVote(String ballot) throws RemoteException, ClientNotFound, InterruptedException {
		Future<Object> clientFuture = null;
		Future<String> serverFuture = null;
		ExecutorService pool = Executors.newCachedThreadPool();
		Set<String> votingClients = clients.keySet();
		
		if (votingClients.size() == 0) {
			log.print(VPrint.WARN, "cannot start evote because no clients are registered");
			return "";
		}
		
		synchronized (currentVotingClients) {
			currentVotingClients.addAll(votingClients);
		}
		
		// hack because concurrentSet is not serializable
		Set<String> votingClientsSer = new HashSet<String>(votingClients);
		EVote evote = new EVote(ballot, votingClientsSer);
		
		Map<String, Future<Object>> clientFutures = new HashMap<String, Future<Object>>();
		
		/**
		 * EVote phase one:
		 * initiates vote by sending evote to each client
		 */
		for (String clientName : votingClients) {
			clientFuture = pool.submit(new clientEVote(getClient(clientName), evote));
			clientFutures.put(clientName, clientFuture);
		}
		
		serverFuture = pool.submit(new serverEVote(evote, votingClients));
		
		/** Do abortion handling... */
		long elapsedTime = 0;
		long startTime = System.currentTimeMillis();
		
		while (!serverFuture.isDone()) {
			elapsedTime = System.currentTimeMillis() - startTime;
			if (elapsedTime > EVOTETIMEOUT * 1000) {
				String reason = String.format("abort vote for ballot %s because took longer than %ssec", evote.id, EVOTETIMEOUT);
				abortEVote(reason, serverFuture, votingClients);
				return "";
			}
			
			for (Entry<String, Future<Object>> entry : clientFutures.entrySet()) {
				String clientName = entry.getKey();
				clientFuture = entry.getValue();
				if (clientFuture.isDone()) {
					try {
						clientFuture.get();
					} catch (ExecutionException e) {
						log.print(VPrint.DEBUG, "ExecutionException: %s", e.getMessage());
						log.print(VPrint.DEBUG, "ExecutionException reason: %s", e.getCause().getMessage());
						// client failed
						String reason = String.format("abort vote for ballot %s because %s failed", evote.id, clientName);
						unregisterClient(clientName);
						abortEVote(reason, serverFuture, votingClients);
						return "";
					}
				}
			}
		}
		
		for (Entry<String, Future<Object>> entry : clientFutures.entrySet()) {
			clientFuture = entry.getValue();
			while (!clientFuture.isDone()) {
				// wait for all clients to finish before we allow server to return
				// small sleep so we don't purely busy wait
				Thread.sleep(100);
			}
		}
		
		String result;
		try {
			result = serverFuture.get();
		} catch (ExecutionException e) {
			result = "";
		}
		
		/** Evote successful! */
		synchronized (currentVotingClients) {
			currentVotingClients.clear();
		}
		
		return result;
	}
	
	/** Abort the vote when necessary */
	private void abortEVote(String abortMessage, Future<String> serverFuture,
			Set<String> votingClients) {
		
		/** make sure a vote is actually going on */
		if (votingClients.size() == 0) {
			return;
		}
		
		log.print(VPrint.DEBUG, "abortEvote(%s)", abortMessage);
		
		log.print(VPrint.ERROR, "%s", abortMessage);
		
		/** Abort client threads */
		for (String clientName: votingClients) {
			try {
				log.print(VPrint.DEBUG, "calling %s.evoteAbort", clientName);
				getClient(clientName).evoteAbort(abortMessage);
			} catch (ClientNotFound e) {
				// do nothing -- client probably died and we automatically unregistered 
			} catch (RemoteException e) {
				// do nothing -- probably the client that failed
			}
		}
		
		/** Abort server thread */
		if (serverFuture != null) {
			serverFuture.cancel(true);
		}
		
		synchronized (currentVotingClients) {
			currentVotingClients.clear();
		}
	}

	public static void main(String args[]) {
		Scanner scan;
		
		if (args.length != 2) {
			System.err.println("usage: java EVoteServer rmiport servername");
			System.exit(1);
		}
		
		try {
			if (System.getSecurityManager() == null) {
				System.setSecurityManager(new SecurityManager());
			}
			
			String rmiHost = InetAddress.getLocalHost().getHostAddress();
			int rmiPort = Integer.parseInt(args[0]);
			String serverName = args[1];
			
			CentralServer server = new EVoteServer(serverName);
			CryptoServer serverStub = (CryptoServer) UnicastRemoteObject
					.exportObject(server, 0);

			// create registry so we don't have to manually start
			// the registry server elsewhere
			Registry registry = LocateRegistry.createRegistry(rmiPort);
			
			registry.rebind(serverName, serverStub); 
			System.out.println(String.format("Running EVote server '%s' at %s:%d", 
					serverName, rmiHost, rmiPort));
			System.out.println("Waiting for client connections...");
			
			/**
			 * Prompt user for ballot
			 */
			scan = new Scanner(System.in);
			
			while (true) {
				System.out.println("Enter ballot:");
				String ballot = scan.nextLine();
				server.initiateEVote(ballot);
			}

		} catch (Exception e) {
			System.err.println("Server exception: " + e.toString());
		}
		
	}

	public static void setTimeout(int to) {
		EVOTETIMEOUT = to;
	}
}