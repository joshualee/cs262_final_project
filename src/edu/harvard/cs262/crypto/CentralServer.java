package edu.harvard.cs262.crypto;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.rmi.registry.Registry;
import java.rmi.registry.LocateRegistry;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.ListIterator;
import java.util.Map;

import edu.harvard.cs262.crypto.CryptoClient;
import edu.harvard.cs262.crypto.ClientNotFound;

public class CentralServer implements CryptoServer {

	private String name;
	private Hashtable<String, CryptoClient> clients;
	private Hashtable<String, LinkedList<String>> notifications;
	private Map<String, Map<String, CryptoMessage>> sessions;
	
	private CentralServer(String name) {
		this.name = name;
		clients = new Hashtable<String, CryptoClient>();
		notifications = new Hashtable<String, LinkedList<String>>();
	}
	
	public String getName() {
		return name;
	}
	
	@Override
	public boolean registerClient(CryptoClient c) throws RemoteException {
		String key = c.getName();
		
		// client with that name already exists
		if (null != clients.get(key)){
			return false;
		}
		
		clients.put(key, c);
		return true;
	}
	
	@Override
	public boolean unregisterClient(String clientName) throws RemoteException{
		
		// client not registered (note: this could also return true)
		if (null == clients.get(clientName)){
			return false;
		}
		
		clients.remove(clientName);
		return true;
	}

	@Override
	public void eavesdrop(String eve, String victim) throws RemoteException, ClientNotFound{
		if(null == clients.get(eve)){
			throw new ClientNotFound(eve + " is not registered.");
		}

		else if(null == clients.get(victim)){
			throw new ClientNotFound(victim + " is not registered.");
		}
				
		else{
			String key = (getClient(eve)).getName();
			String vic = (getClient(victim)).getName();
			LinkedList<String> allVics = notifications.get(key);
			allVics.addLast(victim);
			notifications.put(key,allVics);
		}
	}
	
	@Override
	public void stopEavesdrop(String eve, String victim) throws RemoteException, ClientNotFound{
		if(null == clients.get(eve)){
			throw new ClientNotFound(eve + " is not registered.");
		}
		
		else if(null == clients.get(victim)){
			throw new ClientNotFound(victim + " is not registered.");
		}
				
		else{
			String key = (getClient(eve)).getName();
			String vic = (getClient(victim)).getName();
			LinkedList<String> allVics = notifications.get(key);
			allVics.remove(victim);
			notifications.put(key,allVics);
		}		
	}
	
	@Override
	public void sendMessage(String from, String to, CryptoMessage m) throws RemoteException, ClientNotFound, InterruptedException{
		if(null == clients.get(from)){
			throw new ClientNotFound(from + " is not registered.");
		}
		
		else if(null == clients.get(to)){
			throw new ClientNotFound(to + " is not registered.");
		}
			
		else{
			// first send message to all clients in notification lists (to and from)	
			LinkedList<String> eavesTo = notifications.get(to);
			LinkedList<String> eavesFrom = notifications.get(from);
			
			ListIterator<String> iterTo = eavesTo.listIterator(); 
			while(iterTo.hasNext()){
				(getClient(iterTo.next())).receiveMessage(from, m);
			}
						
			ListIterator<String> iterFrom = eavesFrom.listIterator(); 
			while(iterFrom.hasNext()){
				(getClient(iterFrom.next())).receiveMessage(from,m);
			}			
			
			// finally send message to intended recipient
				(getClient(to)).receiveMessage(from,m);
		}			
	}

	@Override
	public CryptoClient getClient(String clientName) throws RemoteException, ClientNotFound{
		if(null == clients.get(clientName)){
			throw new ClientNotFound(clientName + " is not registered.");
		}
		
		else{
			return clients.get(clientName);
		}
	}

	@Override
	public boolean ping() throws RemoteException{
		return true;
	}
	

	@Override
	public void relaySecureChannel(String from, String to, KeyExchangeProtocol kx, CryptoCipher cipher) throws ClientNotFound, RemoteException, InterruptedException {
		CryptoClient client = getClient(to);
		if (client == null) {
			throw new ClientNotFound(to + " is not registered.");
		}
		
		client.recvSecureChannel(from, kx, cipher);
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
					.exportObject(server);

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
	public void recvMessage(String from, CryptoMessage m)
			throws RemoteException, ClientNotFound, InterruptedException {
		return;
	}

}
