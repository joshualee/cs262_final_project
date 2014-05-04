package edu.harvard.cs262.crypto;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Set;
import java.util.UUID;

import edu.harvard.cs262.crypto.exception.EVoteInvalidResult;

/**
 * 
 * @author joshualee
 * Votes can only have a binary result (pass or no pass)
 */

public class EVote implements Serializable {
	private static final long serialVersionUID = 1L;
	public final int BITS = 32;
	
	// the list of voters
	public Set<String> voters;
	
	// a string description of what the vote is on
	public String ballot;
	public UUID id;
	
	// public parameters: for now we assume we use an evoting scheme that uses ElGamal
	public BigInteger p;
	public BigInteger g;
	
	public EVote(String ballot, Set<String> voters) {
		this.ballot = ballot;
		this.voters = voters;
		
		id = UUID.randomUUID();
		p = BigInteger.valueOf(31123L);
		g = BigInteger.valueOf(2341L);
	}
	
	/**
	 * Returns the number of voters who voted in favor,
	 * given the result of the voting protocol
	 * (we need a few more math tricks to get the actual number)
	 * @return
	 */
	public int countYays(BigInteger result, int numVoters) throws EVoteInvalidResult {
		if (result.equals(BigInteger.valueOf(1))) {
			return 0;
		}
		
		for (int i = 1; i <= numVoters; i++) {
			BigInteger I = BigInteger.valueOf(i);
			BigInteger test = g.modPow(I, p);
			if (test.equals(result)) {
				return i;
			}
		}
		String errorMsg = String.format("%s is not a valid power of %s mod %s", result, g, p);
		throw new EVoteInvalidResult(errorMsg);
		
	}
}
