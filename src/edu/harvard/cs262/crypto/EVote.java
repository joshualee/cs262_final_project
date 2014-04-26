package edu.harvard.cs262.crypto;

import java.math.BigInteger;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * 
 * @author joshualee
 * Votes can only have a binary result (pass or no pass)
 */

public class EVote {
	
	public final int BITS = 32;
	
	// the list of voters
	public Set<String> voters;
	
	// a string description of what the vote is on
	public String ballot;
	public UUID id;
	
	// public parameters
	// TODO: abstract these out?
	public BigInteger p;
	public BigInteger g;
	
	public EVote(String ballot, Set<String> voters) {
		this.ballot = ballot;
		this.voters = voters;
		
		id = UUID.randomUUID();
		p = BigInteger.valueOf(31123L);
		g = BigInteger.valueOf(2341L);
	}
}
