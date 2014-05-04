package edu.harvard.cs262.crypto;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import edu.harvard.cs262.crypto.exception.EVoteInvalidResult;

/**
 * An EVote is an object that represents an e-voting scenario.
 * It includes the voters and ballots involved.
 * Votes can only have a binary result (pass or no pass).
 */

public class EVote implements Serializable {
	private static final long serialVersionUID = 1L;
	public final int BITS = 32;
	
	/** The list of voters */
	public Set<String> voters;
	
	/** A string description of what the vote is over */
	public String ballot;
	public UUID id;
	
	/** Public encryption parameters */
	// TODO: abstract these out?
	public BigInteger p;
	public BigInteger g;
	
	/** Constructor */
	public EVote(String ballot, Set<String> voters) {
		this.ballot = ballot;
		this.voters = voters;
		
		id = UUID.randomUUID();
		p = BigInteger.valueOf(31123L);
		g = BigInteger.valueOf(2341L);
	}
	
	/**
	 * Uses some math tricks to return the number of voters who voted in favor,
	 * given the result of the voting protocol.
	 * @param result
	 * 		This is the result returned by the voting protocol (g^x mod p),
	 * 		where g and p are public encryption parameters and x is the number of people 
	 * 		who voted yes.
	 * @param numVoters
	 * 		This is the number of people who voted.
	 * @return The number of people who voted yes.
	 * @throws EVoteInvalidResult
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
