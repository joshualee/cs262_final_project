package edu.harvard.cs262.crypto;

import java.math.BigInteger;
import java.util.List;
import java.util.UUID;

/**
 * 
 * @author joshualee
 * Votes can only have a binary result (pass or no pass)
 */

public class EVote {
	
	// the list of voters
	public List<String> voters;
	
	// a string description of what the vote is on
	public String ballot;
	public UUID id;
	
	// public parameters
	// TODO: abstract these out?
	public BigInteger p;
	public BigInteger g;
}
