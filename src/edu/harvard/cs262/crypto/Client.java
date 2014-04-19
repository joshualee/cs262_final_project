package edu.harvard.cs262.crypto;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.rmi.registry.Registry;
import java.rmi.registry.LocateRegistry;
import java.util.Hashtable;
import java.util.LinkedList;
import edu.harvard.cs262.crypto.CryptoServer;
import edu.harvard.cs262.crypto.ClientNotFound;

public class Client implements CryptoClient {

	private String name;

	// need setName and getName for CentralServer
	private void setName(String s){
		name = s;
	}
	
	@Override
	public String getName() throws RemoteException{
		return name;
	}
	
	@Override
	public void receiveMessage(String from, CryptoMessage m) throws RemoteException{
	}

	@Override
	public void handshake(String clientName, ProtocolType ptype) throws RemoteException{
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

	  	// args[0]: IP (registry)
			// args[1]: Server name
			// args[2]: Port (registry)
			// args[3]: name
			Client myClient = new Client();
      myClient.setName(args[3]);
	      
    } catch (Exception e) {
      System.err.println("Server exception: " + e.toString());
    }
  }	

}
