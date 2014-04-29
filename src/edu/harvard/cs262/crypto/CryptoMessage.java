package edu.harvard.cs262.crypto;

import java.io.Serializable;

public class CryptoMessage implements Serializable {
	private static final long serialVersionUID = 1L;
	
	private String tag;
	private String sessionID;
	private String plainText;
	private String cipherText;
	
	// some encryption schemes require extra information to accompany message
	private Object encryptionState;

	public CryptoMessage(String ptext, String sid) {
		sessionID = (sid.length() > 0) ? sid : "";
		plainText = ptext;
		cipherText = "";
		tag = "";
	}
	
	public CryptoMessage(String ptext, String ctext, String sid) {
		sessionID = (sid.length() > 0) ? sid : "";
		plainText = ptext;
		cipherText = ctext;
		tag = "";
	}
	
	public String toString() {
		return String.format("session: %s\nplaintext: %s\nciphertext: %s", sessionID, plainText, cipherText);
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
		return cipherText.length() > 0;
	}

	public Object getEncryptionState() {
		return encryptionState;
	}

	public void setEncryptionState(Object encryptionState) {
		this.encryptionState = encryptionState;
	}
	
	
	/**
	 * Tags are a mechanism to give context to the message.
	 * For example an eavesdroping client will be able to
	 * tell what the message is for. This makes the console
	 * application a lot more interesting.
	 * @return
	 */
	public String getTag() {
		return tag;
	}

	public void setTag(String tag) {
		this.tag = tag;
	}
	
	public boolean hasTag() {
		return tag.length() > 0;
	}
}
