package edu.harvard.cs262.crypto;

import java.util.HashMap;
import java.util.Map;

public class InnocentCryptoClient implements CryptoClient {

	private String name;
	private CryptoServer server;
	private Map<String, Integer> keyMap;
	
	public InnocentCryptoClient(String name, CryptoServer server) {
		this.name = name;
		this.server = server;
		this.keyMap = new HashMap<String, Integer>();
	}

	@Override
	public void receiveMessage(String from, CryptoMessage m) {
		if (m.isEncrypted()) {
			int key = keyMap.get(from); 
		}
	}

	@Override
	public boolean ping() {
		return true;
	}

	@Override
	public String getName() {
		return name;
	}
	
	

}
