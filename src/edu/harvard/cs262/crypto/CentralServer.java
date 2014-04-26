package edu.harvard.cs262.crypto;

import java.math.BigInteger;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.rmi.registry.Registry;
import java.rmi.registry.LocateRegistry;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.Callable;
import java.util.Set;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import edu.harvard.cs262.crypto.CryptoClient;
import edu.harvard.cs262.crypto.ClientNotFound;

public class CentralServer implements CryptoServer {
	private String name;
	private Map<String, CryptoClient> clients;
	private Map<String, List<String>> notifications;
	private Map<String, Map<String, CryptoMessage>> sessions;
	
	public CentralServer(String name) {
		this.name = name;
		clients = new ConcurrentHashMap<String, CryptoClient>();
		notifications = new ConcurrentHashMap<String, List<String>>();
		
		Helpers.doAsync(new Runnable() { public void run() {
			try {
				heartbeatClients(1, 2, 1);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}});
	}
	
	@Override
	public String getName() throws RemoteException {
		return name;
	}
	
	@Override
	public String getClients() throws RemoteException{
		String ret = "";
		Set<String> clientSet = clients.keySet();
		String[] clientArray = clientSet.toArray(new String[0]);
		Arrays.sort(clientArray);
		for(String temp: clientArray){
			ret += "\n" + temp;
		}
					
		return ret;
	}
	
	@Override
	public boolean registerClient(CryptoClient c) throws RemoteException {
		String clientName = c.getName();
		
		// client with that name already exists
		if (clients.containsKey(clientName)){
			System.out.println("Client with name " + clientName + " already exists");
			return false;
		}
		
		clients.put(clientName, c);
		// TODO: possible race condition if we context switch here
		// and client is in client list but not in notification map
		List<String> newList = new LinkedList<String>();
		notifications.put(clientName, newList);
		
		System.out.println("Registered new client: " + clientName);
		return true;
	}
	
	@Override
	public boolean unregisterClient(String clientName) throws RemoteException {
		// client not registered (note: this could also return true)
		if (!clients.containsKey(clientName)){
			return false;
		}
		
		clients.remove(clientName);
		notifications.remove(clientName);
		for (List<String> clientList : notifications.values()) {
			clientList.remove(clientName);
		}
		
		return true;
	}
	
	private class ClientPingCallable implements Callable<Boolean> {
		private CryptoClient client;
		public ClientPingCallable(CryptoClient client) {
			this.client = client;
		}
		
		public Boolean call() throws RemoteException {
			System.out.println(String.format("Pinging %s...", client.getName()));
			return client.ping();
		}
	}
	
	/**
	 * Ping clients and remove from client list if unresponsive
	 * @throws RemoteException 
	 * @throws InterruptedException 
	 */
	private void heartbeatClients(int frequency, int maxFails, int pingTimeout) throws RemoteException, InterruptedException {
		int failCount;
		CryptoClient client;
		String clientName;
		Future<?> pingFuture;
		
		ExecutorService pool = Executors.newCachedThreadPool();
		Map<String, Future<?>> futureMap = new ConcurrentHashMap<String, Future<?>>();
		
		// keep track of the number of failed pings per client
		Map<String, Integer> failedAttempts = new ConcurrentHashMap<String, Integer>();
		
		while (true) {
			Thread.sleep(frequency * 1000);
			
			futureMap.clear();
			
			/*
			 * Ping all clients
			 */
			for (final Entry<String, CryptoClient> entry : clients.entrySet()) {
				clientName = entry.getKey();
				client = entry.getValue();
				
				
				// TODO: wrap this in a class...
				pingFuture = pool.submit(new ClientPingCallable(client));
				
				futureMap.put(clientName, pingFuture);
			}
			
			/*
			 * Ensure ping went through
			 */
			for (Entry<String, Future<?>> entry : futureMap.entrySet()) {
				clientName = entry.getKey();
				pingFuture = entry.getValue();
				
				try {
					pingFuture.get(pingTimeout, TimeUnit.SECONDS);
					
					System.out.println(String.format("%s responded to ping", clientName));
					
					// the client successfully responded to the ping 
					failedAttempts.put(clientName, 0);
				}
				catch (Exception e) {
					/*
					 * The client either (1) didn't respond to ping in time
					 * or (2) threw an error such as RMI Remote exception  
					 */
					failCount = failedAttempts.containsKey(clientName) ?
							failedAttempts.get(clientName) + 1 : 1;
					
					System.out.println(String.format("%s failed ping (%d)", clientName, failCount));
					
					if (failCount >= maxFails) {
						unregisterClient(clientName);
						failedAttempts.remove(clientName);
					} 
					else {
						failedAttempts.put(clientName, failCount);
					}
				}
			}
		}
	}
	
	private void assertClientRegistered(String clientName) throws ClientNotFound {
		if (!clients.containsKey(clientName)) {
			throw new ClientNotFound(clientName + " is not registered.");
		}
	}

	@Override
	public void eavesdrop(String listener, String victim) throws RemoteException, ClientNotFound {
		assertClientRegistered(listener);
		assertClientRegistered(victim);
		
		// TODO: assumes if victim is a client, then vicList won't be null
		List<String> vicList = notifications.get(victim);
			
		if (!vicList.contains(listener)) {
			vicList.add(listener);
		}
		else {
			System.out.println(String.format("Warning: %s is already listening to %s", listener, victim));
		}
	}
	
	@Override
	public void stopEavesdrop(String listener, String victim) throws RemoteException, ClientNotFound{
		assertClientRegistered(listener);
		assertClientRegistered(victim);
		
		List<String> vicList = notifications.get(victim);
		vicList.remove(listener);
	}
	
	private void relayMessage(String relayTarget, String from, String to, CryptoMessage m) throws RemoteException, InterruptedException, ClientNotFound {
		List<String> listeners = notifications.get(relayTarget);
		for (String cname : listeners) {
			getClient(cname).recvMessage(from, to, m);
		}
	}
	
	@Override
	public void sendMessage(String from, String to, CryptoMessage m) throws RemoteException, ClientNotFound, InterruptedException {
		assertClientRegistered(from);
		assertClientRegistered(to);
		
		// first send message to all clients in notification lists (to and from)
		relayMessage(to, from, to, m);
		relayMessage(from, from, to, m);

		// finally send message to intended recipient
		getClient(to).recvMessage(from, to, m);			
	}

	@Override
	public CryptoClient getClient(String clientName) throws RemoteException, ClientNotFound {
		assertClientRegistered(clientName);
		return clients.get(clientName);
	}

	@Override
	public boolean ping() throws RemoteException{
		return true;
	}
	

	@Override
	public void relaySecureChannel(String from, String to, KeyExchangeProtocol kx, CryptoCipher cipher) throws ClientNotFound, RemoteException, InterruptedException {
		assertClientRegistered(from);
		assertClientRegistered(to);
		
		getClient(to).recvSecureChannel(from, kx, cipher);
	}	
	
	/**
	 * Blocks until all registered clients have sent a message with sid 
	 * @param sid the session id to wait on
	 * @throws InterruptedException 
	 */
	
	public Map<String, CryptoMessage> waitForAll(String sid) throws InterruptedException {
		while (!sessions.containsKey(sid)) {
			sessions.wait();
		}
		
		Map<String, CryptoMessage> clientMap = sessions.get(sid);
		
		for (String client : clients.keySet()) {
			while (!clientMap.containsKey(client)) {
				clientMap.wait();
			}
		}
		
		clientMap = sessions.remove(sid);
		clientMap.notifyAll();
		
		return clientMap;
	}
	
	public CryptoMessage waitForMessage(String from, String sid) throws InterruptedException {
		while (!sessions.containsKey(sid)) {
			sessions.wait();
		}
		
		Map<String, CryptoMessage> clientMap = sessions.get(sid);
		
		while (!clientMap.containsKey(from)) {
			clientMap.wait();
		}
		
		CryptoMessage m = clientMap.remove(from);
		sessions.notifyAll();
		
		return m;
	}

	
	public void recvMessage(String from, CryptoMessage m) throws RemoteException, ClientNotFound, InterruptedException {
		if (m.hasSessionID()) {
			String sid = m.getSessionID();
			
			// TODO: potential race condition if two new session IDs
			// come in at the same time...
			// both will make new sessionMaps
			Map<String, CryptoMessage> sessionMap = sessions.get(sid);
			
			if (sessionMap == null) {
				sessionMap = new Hashtable<String, CryptoMessage>();
				sessions.put(sid, sessionMap);
			}
			
			while (sessionMap.containsKey(from)) {
				System.out.println("Warning: (session, client) (" + sid + ", " + from + ") already has a waiting message");
				sessionMap.wait();
			}
			sessionMap.put(from, m);
			return;
		}
		
		System.out.println(from + ": " + m.getPlainText());
	}
	
	private class clientEVote implements Runnable {
		private CryptoClient client;
		private EVote evote;
		
		public clientEVote(CryptoClient client, EVote evote) {
			this.client = client;
			this.evote = evote;
		}
		
		public void run() {
			try {
				client.eVote(evote);
			} 
			catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
	
	public void initiateEVote(String ballot) throws RemoteException, ClientNotFound, InterruptedException {
		ExecutorService pool = Executors.newCachedThreadPool();
		Set<String> votingClients = clients.keySet();
		EVote evote = new EVote(ballot, votingClients);
		
		String sid = evote.id.toString();
		
		/*
		 * EVote phase one:
		 * initiates vote by sending evote to each client
		 */
		for (String clientName : votingClients) {
			pool.execute(new clientEVote(getClient(clientName), evote));			
		}
		
		/*
		 * EVote phase 3:
		 * server receives g^(sk_i) from each client and calculates shared public key
		 */
		
		// TODO: wait for all should take list of clients
		Map<String, CryptoMessage> pkMsgs = waitForAll(sid);
		BigInteger publicKey = BigInteger.valueOf(1L);
		for (CryptoMessage pkMsg : pkMsgs.values()) {
			BigInteger pk = new BigInteger(pkMsg.getPlainText());
			publicKey = publicKey.multiply(pk).mod(evote.p);
		}
		
		CryptoMessage publicKeyMessage = new CryptoMessage(publicKey.toString(), sid);
		
		// TODO: broadcast function
		for (String clientName: votingClients) {
			getClient(clientName).recvMessage(name, clientName, publicKeyMessage);
		}
		
		/*
		 * EVote phase 4:
		 * server combines c_i from clients to form combined cipher text
		 */
		Map<String, CryptoMessage> cipherMsgs = waitForAll(sid);
		BigInteger c1 = BigInteger.valueOf(1L);
		BigInteger c2 = BigInteger.valueOf(1L);
		for (CryptoMessage cipherMsg : cipherMsgs.values()) {
			BigInteger c1_i = (BigInteger) cipherMsg.getEncryptionState();
			BigInteger c2_i = new BigInteger(cipherMsg.getPlainText());
			c1 = c1.multiply(c1_i).mod(evote.p);
			c2 = c2.multiply(c2_i).mod(evote.p);
		}
		
		CryptoMessage combinedCipherMsg = new CryptoMessage(c2.toString(), sid);
		combinedCipherMsg.setEncryptionState(c1);
		
		for (String clientName: votingClients) {
			getClient(clientName).recvMessage(name, clientName, combinedCipherMsg);
		}
		
		/*
		 * EVote phase 7:
		 * compute the decryption key and share with all clients
		 */
		
		Map<String, CryptoMessage> decryptMsgs = waitForAll(sid);
		BigInteger decrypt = BigInteger.valueOf(1L);
		for (CryptoMessage decryptMsg : decryptMsgs.values()) {
			BigInteger decrypt_i = new BigInteger(decryptMsg.getPlainText());
			decrypt = decrypt.multiply(decrypt_i).mod(evote.p);
		}
		
		CryptoMessage decryptKeyMsg = new CryptoMessage(decrypt.toString(), sid);
		for (String clientName: votingClients) {
			getClient(clientName).recvMessage(name, clientName, decryptKeyMsg);
		}
		
		// TODO: do decryption myself to check result...
		
		
	}
	
	public static void main(String args[]) {
		if (args.length != 2) {
			System.err.println("usage: java CentralServer rmiport servername");
			System.exit(1);
		}

		try {
			if (System.getSecurityManager() == null) {
				System.setSecurityManager(new SecurityManager());
			}
			
			int registryPort = Integer.parseInt(args[0]);
			String serverName = args[1];
			
			CentralServer server = new CentralServer(serverName);
			CryptoServer serverStub = (CryptoServer) UnicastRemoteObject
					.exportObject(server, 0);

			// create registry so we don't have to manually start
			// the registry server elsewhere
			Registry registry = LocateRegistry.createRegistry(registryPort);
			
			// rebind to avoid AlreadyBoundException
			registry.rebind(serverName, serverStub); 
			System.out.println("Server ready");

		} catch (Exception e) {
			System.err.println("Server exception: " + e.toString());
		}
	}

	@Override
	public void recvMessage(String from, String to, CryptoMessage m)
			throws RemoteException, ClientNotFound, InterruptedException {
		return;
	}
}
