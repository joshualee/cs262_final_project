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
	
	private CentralServer(){
		super();
		clients = new Hashtable<String, CryptoClient>();
		notifications = new Hashtable<String, LinkedList<String>>();
	}
	
	@Override
	public boolean registerClient(CryptoClient c) throws RemoteException{
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

      CentralServer server = new CentralServer();
      CryptoServer serverStub = (CryptoServer)UnicastRemoteObject.exportObject(server);
      
      // args[0]: IP (registry)
			// args[1]: Server name
			// args[2]: Port (registry)
			
      String serverName = args[1];
      Registry registry = LocateRegistry.getRegistry(args[0]);
      registry.rebind(serverName, serverStub); // rebind to avoid AlreadyBoundException
      System.out.println("Server ready");

	      
    } catch (Exception e) {
      System.err.println("Server exception: " + e.toString());
    }
  }	

}
