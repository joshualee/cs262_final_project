package edu.harvard.cs262.crypto;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.rmi.registry.Registry;
import java.rmi.registry.LocateRegistry;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.ListIterator;
import edu.harvard.cs262.crypto.CryptoClient;
import edu.harvard.cs262.crypto.ClientNotFound;

public class CentralServer implements CryptoServer {

	private Hashtable<String, CryptoClient> clients;
	private Hashtable<String, LinkedList<String>> notifications;
	private LinkedList<CryptoServer> serverList;
	private String name;
	private boolean is_primary;

	private CentralServer(String name, boolean p){
		this.name = name;
		is_primary = p
		clients = new Hashtable<String, CryptoClient>();
		notifications = new Hashtable<String, LinkedList<String>>();
	}

	public String getName(){
		return name
	}
	
	public boolean updateServerList(CryptoServer s, boolean add) throws RemoteException{
		ListIterator<String> iterServers = serverList.listIterator(); 
		while(iterServers.hasNext()){
			serv = iterServers.next();
			if (serv == this){
				continue;
			}
			if (add){
				(serv.getServerList()).addLast(s);
			}
			else {
				(serv.getServerList()).remove(s)
			}

		}
		return true
	}

	public boolean updateNotifications() throws RemoteException{
		ListIterator<String> iterServers = serverList.listIterator(); 
		while(iterServers.hasNext()){
			serv = iterServers.next();
			if (serv == this){
				continue;
			}
			

		}
	}

	@Override
	public boolean registerClient(CryptoClient c) throws RemoteException{

		String key = c.getName();
		
		// client with that name already exists
		if (null != clients.get(key)){
			return false;
		}
		
		if (is_primary){
			ListIterator<String> iterServers = serverList.listIterator(); 
			while(iterServers.hasNext()){
				serv = iterServers.next();
				if (serv != this){
					success = serv.registerClient(c);
					if (!success){
						updateServerList(serv, false);

					}

				}
			}
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
		if (is_primary){
			ListIterator<String> iterServers = serverList.listIterator(); 
			while(iterServers.hasNext()){
				serv = iterServers.next();
				if (serv != this){
					success = serv.unregisterClient(c);
					if (!success){
						updateServerList(serv, false);

					}

				}
			}
		}
		
		clients.remove(clientName);
		return true;
	}

	public String getServerList() throws RemoteException{
		return serverList;
	}

	public String getClients() throws RemoteException{
		return clients;
	}

	public String getNotifications() throws RemoteException{
		return notifications;
	}

	public boolean registerBackup(CryptoServer backup) {
		serverList.add(backup);

		backup.updateNotifications()
		backup.updateClients()

		if (is_primary) {
			for (CryptoServer server : serverList) {
				server.registerBackup(backup);
			}
		}
	}

	public boolean registerSelf(CryptoServer primary) throws RemoteException{
		// server is already registered
		slist = primary.getServerList();
		if (slist.contains(this)){
			return false;
		}
		slist.addLast(this);
		serverList = slist;
		clients = primary.getClients();
		notifications = primary.getNotifications();
		// slist.addLast(this);
		primary.updateServerList(this,true);
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
			if (is_primary){
				ListIterator<String> iterServers = serverList.listIterator(); 
				while(iterServers.hasNext()){
					serv = iterServers.next();
					if (serv != this){
						success = serv.eavesdrop(eve,victim);
						if (!success){
							updateServerList(serv, false);

						}

					}
				}
			}

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
			if (is_primary){
				ListIterator<String> iterServers = serverList.listIterator(); 
				while(iterServers.hasNext()){
					serv = iterServers.next();
					if (serv != this){
						success = serv.stopEavesdrop(eve,victim);
						if (!success){
							updateServerList(serv, false);

						}

					}
				}
			}
		}		
	}
	
	@Override
	public void sendMessage(String from, String to, CryptoMessage m) throws RemoteException, ClientNotFound{
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

  public static void main(String args[]){
    try {
      if (System.getSecurityManager() == null) {
        System.setSecurityManager(new SecurityManager());
      }

      CentralServer server1 = new CentralServer(server1, true);
      CentralServer server2 = new CentralServer(server2, false);
      CentralServer server3 = new CentralServer(server3, false);
      CryptoServer serverStub1 = (CryptoServer)UnicastRemoteObject.exportObject(server);
      CryptoServer serverStub2 = (CryptoServer)UnicastRemoteObject.exportObject(server);
      CryptoServer serverStub3 = (CryptoServer)UnicastRemoteObject.exportObject(server);





      server1.registerSelf(server1);
      server2.registerSelf(server1);
      server3.registerSelf(server1);
      
      // args[0]: IP (registry)
			// args[1]: Server name
			// args[2]: Port (registry)
			
      //TODO
      String serverName = args[1];
      Registry registry = LocateRegistry.getRegistry(args[0]);
      registry.rebind(serverName, serverStub); // rebind to avoid AlreadyBoundException
      System.out.println("Server ready");

	      
    } catch (Exception e) {
      System.err.println("Server exception: " + e.toString());
    }
  }	

}
