package edu.harvard.cs262.crypto.server;

import java.net.InetAddress;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.rmi.registry.Registry;
import java.rmi.registry.LocateRegistry;
import java.util.LinkedList;
import java.util.List;
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

import edu.harvard.cs262.crypto.CryptoMessage;
import edu.harvard.cs262.crypto.Helpers;
import edu.harvard.cs262.crypto.VPrint;
import edu.harvard.cs262.crypto.cipher.CryptoCipher;
import edu.harvard.cs262.crypto.cipher.KeyExchangeProtocol;
import edu.harvard.cs262.crypto.client.CryptoClient;
import edu.harvard.cs262.crypto.exception.ClientNotFound;

/**
 * A server that relays messages between clients and sends messages to eavesdropping clients.
 * Designed to work with DHCryptoClient
 *
 * @author Holly Anderson, Joshua Lee, and Tracy Lu
 */
public class CentralServer implements CryptoServer {
	// sets the level of console printing 
	protected final static int VERBOSITY = VPrint.WARN; 
	
	protected String name;
	protected VPrint log;
	
	/* List of all clients */
	protected Map<String, CryptoClient> clients;
	
	/* Hashmap with clients as keys and lists of who is eavedropping on them as values*/
	protected Map<String, List<String>> notifications;
	
	public CentralServer(String name) {
		this.name = name;
		
		String logName = String.format("%s %s.log", name, Helpers.currentTimeForFile());
		log = new VPrint(VERBOSITY, logName);
		clients = new ConcurrentHashMap<String, CryptoClient>();
		notifications = new ConcurrentHashMap<String, List<String>>();
		
		/* Checks to see if any clients have failed by pinging them */
		Executors.newSingleThreadExecutor().submit(new Runnable() { public void run() {
			try {
				heartbeatClients(2, 2, 1);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}});
	}
	
	public String getName() throws RemoteException {
		return name;
	}

	/**
	 * Returns the list of currently registered clients.
	 * 
	 * @param arrayFormat
	 * 		the desired string output format
	 * @return the list of registered clients as a string
	 * @throws RemoteException
	 */
	public String getClientList(boolean arrayFormat) throws RemoteException {
		String delim;

		if(arrayFormat) {
			delim = ", ";
		}
		else {
			delim = "\n";
		}
		
		String clientString = "";
		Set<String> clientSet = clients.keySet();
		String[] clientArray = clientSet.toArray(new String[0]);
		Arrays.sort(clientArray);
		
		for (int i = 0; i < clientArray.length; i++) {
			if (i != clientArray.length - 1) {
				clientString += (clientArray[i] + delim);	
			} else {
				clientString += clientArray[i];
			}	
		}
		
		if(arrayFormat){
			clientString = "[" + clientString + "]";
		}
		return clientString;
	}
	
	/**
	 * Returns a reference to the client with the specified name. This is needed when a client 
	 * wants to communicate with another client directly and not have to go through the server.
	 * This function should be used with care, as it bypasses the server layer, which in general should
	 * not be done.
	 * 
	 * @param clientName
	 * 		the name of the client
	 * @return a reference to the client object
	 * @throws RemoteException, ClientNotFound
	 */
	public CryptoClient getClient(String clientName) throws RemoteException, ClientNotFound {
		assertClientRegistered(clientName);
		return clients.get(clientName);
	}

	/**
	 * Used to ensure the server is responsive. Only returns true, but may never return if the
	 * server has crashed or just doesn't respond.
	 * 
	 * @return
	 * 		true, meaning the server is alive
	 * @throws RemoteException
	 */
	public boolean ping() throws RemoteException{
		return true;
	}	
	
	/**
	 * Register a remote client so server can forward it messages.
	 * Function is designed to be called by the client.
	 * Clients must first register before using any of the other server functionality.
	 * 
	 * @param c the registering client 
	 * @return true if the client successfully registered
	 */
	public boolean registerClient(CryptoClient c) throws RemoteException {
		String clientName = c.getName();
		
		/*
		 * Fails if client with that name already exists
		 */
		if (clients.containsKey(clientName)) {
			log.print(VPrint.ERROR, "client with name %s already exists", clientName);
			return false;
		}
		
		/*
		 *  Before adding client to client list, we lock notifications
		 *  because if we context switch after adding client to clients but
		 *  before we add an entry in the notification map, then someone
		 *  may try to eavesdrop and we have a race condition for the notification reference
		 */
		synchronized (notifications) {
			clients.put(clientName, c);
			List<String> newList = new LinkedList<String>();
			notifications.put(clientName, newList);
		}
		
		log.print(VPrint.QUIET, "registered new client: %s", clientName);
		log.print(VPrint.QUIET, "clients: %s", getClientList(true));
		return true;
	}
	
	/**
	 * Unregister a remote client so server can no longer forward it messages.
	 * 
	 * @param c the unregistering client 
	 * @return true if the client successfully unregistered
	 */
	public boolean unregisterClient(String clientName) throws RemoteException {
		// client not registered (note: this could also return true)
		if (!clients.containsKey(clientName)) {
			return false;
		}
		
		clients.remove(clientName);
		notifications.remove(clientName);
		for (List<String> clientList : notifications.values()) {
			clientList.remove(clientName);
		}

		log.print(VPrint.QUIET, "unregistered client: %s", clientName);
		log.print(VPrint.QUIET, "clients: %s", getClientList(true));
		return true;
	}
	
	/**
	 * Make sure a client is registered and throw an exception if it is not.
	 * 
	 * @param clientName
	 * @throws ClientNotFound
	 */
	private void assertClientRegistered(String clientName) throws ClientNotFound {
		if (!clients.containsKey(clientName)) {
			throw new ClientNotFound(clientName + " is not registered.");
		}
	}
	
	/**
	 * Helper method to relay messages to support eavesdropping.
	 * 
	 * @param relayTarget
	 * 		the eavesdropper
	 * @param from
	 * 		the original sender
	 * @param to
	 * 		the intended recipient
	 * @param m
	 * 		the message
	 * @throws RemoteException, InterruptedException, ClientNotFound
	 */
	private void relayMessage(String relayTarget, String from, String to, CryptoMessage m) throws RemoteException, InterruptedException, ClientNotFound {
		List<String> listeners = notifications.get(relayTarget);
		for (String cname : listeners) {
			getClient(cname).recvMessage(from, to, m);
		}
	}
	
	/** 
	 * CentralServer doesn't implement receive messages
	 */
	public String recvMessage(String from, String to, CryptoMessage m) throws RemoteException, ClientNotFound, InterruptedException {
		log.print(VPrint.ERROR, "central server does not implement receive messages");
		return "";
	}
	
	/**
	 * Send message "m" from client "from" to client "to".
	 * Blocks until message has successfully been delivered.
	 * Returns the message being sent, so the caller may check
	 * the integrity of the call
	 * 
	 * @param from: the name of the client sending the message
	 * @param to: the name of the client receiving the message
	 * @param m: the message being sent
	 * @return The message sent
	 * @throws RemoteException, ClientNotFound, InterruptedException 
	 */
	public String sendMessage(String from, String to, CryptoMessage m) throws RemoteException, ClientNotFound, InterruptedException {
		assertClientRegistered(from);
		assertClientRegistered(to);
		
		/* First send message to all clients in notification lists (to and from) */
		relayMessage(to, from, to, m);
		relayMessage(from, from, to, m);

		String msg;
		/* Finally send message to intended recipient */
		try {
			msg = getClient(to).recvMessage(from, to, m);
		} catch (RemoteException e) {
			// client failed before we detected failure using ping
			throw new ClientNotFound(String.format("server unable to reach client %s", to));
		}
		
		return msg;			
	}	

	/** 
	 * Waiting for messages is only relevant to e-voting
	 */
	public Map<String, CryptoMessage> waitForAll(String sid) throws InterruptedException {
		log.print(VPrint.ERROR, "central server does not implement waiting for messages");
		return null;
	}
	
	/** 
	 * Waiting for messages is only relevant to e-voting
	 */
	public CryptoMessage waitForMessage(String from, String sid) throws InterruptedException {
		log.print(VPrint.ERROR, "central server does not implement waiting for messages");
		return null;
	}

	/**
	 * Allow client "listener" to listen to all incoming and outgoing communication of client 
	 * "victim". Once a client has registered to eavesdrop, the server will automatically forward
	 * all communications to/from "victim" to "listener"
	 * 
	 * Adds client to the proper eavesdropping list.
	 * 
	 * @param listener
	 * 		name of client listening
	 * @param victim
	 * 		name of client to listen to
	 * @throws RemoteException, ClientNotFound
	 */
	public void eavesdrop(String listener, String victim) throws RemoteException, ClientNotFound {
		assertClientRegistered(listener);
		assertClientRegistered(victim);
		
		List<String> vicList = notifications.get(victim);
		
		if (vicList == null) {
			// this should never happen because of our synchronization
			log.print(VPrint.ERROR, "Notifications for %s have not yet been allocated. " +
					"Potential race condition", victim);
		}
		
		if (!vicList.contains(listener)) {
			vicList.add(listener);
		}
		else {
			log.print(VPrint.WARN, "%s is already listening to %s", listener, victim);
		}
	}
	
	/**
	 * Allow client "listener" to stop listening to communications of client "victim"
	 * 
	 * Removes client from the proper eavesdropping list.
	 * 
	 * @param listener
	 * 		name of client no longer listening
	 * @param victim
	 * 		name of client to no longer listen to
	 * @throws RemoteException, ClientNotFound
	 */
	public void stopEavesdrop(String listener, String victim) throws RemoteException, ClientNotFound {
		assertClientRegistered(listener);
		assertClientRegistered(victim);
		
		List<String> vicList = notifications.get(victim);
		vicList.remove(listener);
	}

	/**
	 * Relay a request from client "from" to create a secure channel with client "to" that
	 * uses the KeyExchangeProtocol "kx" and CryptoCipher "c". This is a remote method intended
	 * to be called by the client who wishes to create the secure channel.
	 * 
	 * @param from
	 * 		the name of the client requesting to create the secure channel
	 * @param to
	 * 		the name of the client targeted to create the secure channel with
	 * @param kx
	 * 		the key exchange protocol being used
	 * @param c
	 * 		the crypto cipher being used
	 * @throws ClientNotFound, RemoteException, InterruptedException
	 */
	public void relaySecureChannel(String from, String to, KeyExchangeProtocol kx, CryptoCipher cipher) throws ClientNotFound, RemoteException, InterruptedException {
		assertClientRegistered(from);
		assertClientRegistered(to);
		
		getClient(to).recvSecureChannel(from, kx, cipher);
	}	

	/** 
	 * The CentralServer does not handle e-voting
	 */
	public String initiateEVote(String ballot) throws RemoteException, ClientNotFound, InterruptedException {
		log.print(VPrint.ERROR, "central server does not implement evoting");
		return "";
	}
	
	/** Create a Callable object used to ping clients */
	private class ClientPingCallable implements Callable<Boolean> {
		private CryptoClient client;
		public ClientPingCallable(CryptoClient client) {
			this.client = client;
		}
		
		public Boolean call() throws RemoteException {
			log.print(VPrint.DEBUG2, "pinging %s...", client.getName());
			return client.ping();
		}
	}
	
	/**
	 * Ping clients and remove from client list if unresponsive. This is done in a separate thread
	 * that starts up when the server is initialized.
	 * 
	 * @param frequency: how often to ping
	 * @param maxFails: the max number of failures to respond before a client is removed
	 * @param pingTimeout: how long to wait for a response to a ping
	 * @throws RemoteException 
	 * @throws InterruptedException 
	 */
	protected void heartbeatClients(int frequency, int maxFails, int pingTimeout) throws RemoteException, InterruptedException {
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
					
					log.print(VPrint.DEBUG2, "%s responded to ping", clientName);
					
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
					
					
					log.print(VPrint.LOUD, "%s failed ping (%d)", clientName, failCount);
					
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
	
	/*
	 * Console line application to facilitate client to client interactions
	 */
	public static void main(String args[]) {
		if (args.length != 2) {
			System.err.println("usage: java CentralServer rmiport servername");
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
			
			// rebind to avoid AlreadyBoundException
			registry.rebind(serverName, serverStub);
			
			System.out.println(String.format("Running central server '%s' at %s:%d", 
					serverName, rmiHost, registryPort));

		} catch (Exception e) {
			System.err.println("Server exception: " + e.toString());
		}
	}
}
