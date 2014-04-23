package edu.harvard.cs262.crypto;

public class KeyExchangeNotSupported extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private String keyExchange;
	
	public KeyExchangeNotSupported(String s) {
		keyExchange = s;
	}

}
