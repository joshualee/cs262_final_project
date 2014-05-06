package edu.harvard.cs262.crypto.client;

/**
 * Represents pair of clients in a given communication
 * 
 * References
 * (1) hashCode() adapted from post by user 'arturh' at 
 * http://stackoverflow.com/questions/156275/what-is-the-equivalent-of-the-c-pairl-r-in-java
 * (2) equals(Object c) adapted from http://www.javaranch.com/journal/2002/10/newsletteroct2002.jsp#equalandhash
 *
 * @author Holly Anderson, Joshua Lee, and Tracy Lu
 */
public class ClientPair {

	private String from;
	private String to;

	public ClientPair(String from, String to) {
		this.from = from;
		this.to = to;
	}
	
	public String toString() {
		return "From: " + from + ", To: " + to;		
	}
	
	/**
	 * Returns hashcode for the ClientPair
	 * @return an int hashcode
	 */
	public int hashCode() {
		int hashFrom = from != null ? from.hashCode() : 0;
		int hashTo = to != null ? to.hashCode() : 0;
		return (hashFrom + hashTo) * hashTo + hashFrom;
	}
	
	/**
	 * Checks to see if the ClientPair is equal to another Object c
	 * @return true if equal, otherwise false
	 */
	public boolean equals(Object c) {
		if(this==c){
			return true;
		}
		if((c == null) || (this.getClass() != c.getClass())){
			return false;
		}
		ClientPair cp = (ClientPair)c;
		return (from.equals(cp.from) && to.equals(cp.to));
	}
	
	public String getFrom() {
		return from;
	}
	
	public String getTo() {
		return to;
	}
}
