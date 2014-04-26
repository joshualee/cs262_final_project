package edu.harvard.cs262.crypto;

// hashCode() adapted from http://stackoverflow.com/questions/156275/what-is-the-equivalent-of-the-c-pairl-r-in-java
// equals(Obj c) adapted from http://www.javaranch.com/journal/2002/10/newsletteroct2002.jsp#equalandhash
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
	
	@Override
	public int hashCode() {
		int hashFrom = from != null ? from.hashCode() : 0;
		int hashTo = to != null ? to.hashCode() : 0;
		return (hashFrom + hashTo) * hashTo + hashFrom;
	}
	
	@Override
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
		return this.from;
	}
	
	public String getTo() {
		return this.to;
	}

}
