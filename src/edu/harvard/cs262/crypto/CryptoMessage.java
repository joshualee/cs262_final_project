package edu.harvard.cs262.crypto;

import java.io.Serializable;

/**
 * A CryptoMessage represents messages that are sent between clients.
 * It can be encrypted or not encrypted.
 * If message is not encrypted, the message is stored in the variable {@code plainText} 
 * If message is encrypted, the encrypted message is stored in {@code cipherText} and 
 * the plaintext is also stored for testing purposes
 *
 */
public class CryptoMessage implements Serializable {
	private static final long serialVersionUID = 1L;
	
	/**
	 * The tag describes what the message is for. They are useful for debugging and organization.
	 * An eavesdropping client will also be able to tell what the message is for. 
	 * This makes the console application a lot more interesting.
	 */
	private String tag;
	private String sessionID;
	private String plainText;
	private String cipherText;
	
	/** This object stores extra information that is required by some encryption schemes */
	private Object encryptionState;

	/** Constructor for non-encrypted message */
	public CryptoMessage(String ptext, String sid) {
		sessionID = (sid.length() > 0) ? sid : "";
		plainText = ptext;
		cipherText = "";
		tag = "";
	}
	
	/** Constructor for encrypted message */
	public CryptoMessage(String ptext, String ctext, String sid) {
		sessionID = (sid.length() > 0) ? sid : "";
		plainText = ptext;
		cipherText = ctext;
		tag = "";
	}
	
	/** Converts the object into a readable string
	 * @return A string that contains session ID, and plain and cipher texts of the message
	 */
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
