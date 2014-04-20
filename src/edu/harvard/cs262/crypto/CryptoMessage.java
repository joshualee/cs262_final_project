package edu.harvard.cs262.crypto;

public class CryptoMessage {
	
	private String sessionID;
	private String plainText;
	private String cipherText;

	public CryptoMessage(String ptext) {
		sessionID = "";
		plainText = ptext;
		cipherText = "";
	}
	
	public String getSessionID() {
		return sessionID;
	}


	public void setSessionID(String sessionID) {
		this.sessionID = sessionID;
	}


	public String getPlainText() {
		return plainText;
	}


	public void setPlainText(String plainText) {
		this.plainText = plainText;
	}


	public String getCipherText() {
		return cipherText;
	}


	public void setCipherText(String cipherText) {
		this.cipherText = cipherText;
	}
}
