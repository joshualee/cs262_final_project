package edu.harvard.cs262.crypto;

public class CryptoMessage {
	
	private String sessionID;
	private String plainText;
	private String cipherText;
	
	// some encryption schemes require extra information to accompany message
	private Object encryptionState;

	public CryptoMessage(String ptext, String sid) {
		sessionID = (sid.length() > 0) ? sid : "";
		plainText = ptext;
		cipherText = "";
	}
	
	public CryptoMessage(String ptext, String ctext, String sid) {
		sessionID = (sid.length() > 0) ? sid : "";
		plainText = ptext;
		cipherText = ctext;
	}
	
	public boolean hasSessionID() {
		return sessionID.length() > 0;
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
	
	public boolean isEncrypted() {
		return cipherText != "";
	}

	public Object getEncryptionState() {
		return encryptionState;
	}

	public void setEncryptionState(Object encryptionState) {
		this.encryptionState = encryptionState;
	}
}
