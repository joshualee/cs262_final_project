package edu.harvard.cs262.crypto;

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
import java.util.concurrent.ConcurrentHashMap;

import edu.harvard.cs262.crypto.CryptoClient;
import edu.harvard.cs262.crypto.ClientNotFound;

public class CentralServer implements CryptoServer {

	private String name;
	private Map<String, CryptoClient> clients;
	private Map<String, List<String>> notifications;
	private Map<String, Map<String, CryptoMessage>> sessions;
	
	private CentralServer(String name) {
		this.name = name;
		clients = new ConcurrentHashMap<String, CryptoClient>();
		notifications = new ConcurrentHashMap<String, List<String>>();
	}
	
	public String getName() throws RemoteException {
		return name;
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
	
	/*
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
