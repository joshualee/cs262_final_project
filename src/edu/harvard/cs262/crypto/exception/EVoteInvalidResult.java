package edu.harvard.cs262.crypto.exception;

/**
 * Thrown when the result of the evote is not decodeable. This most likely
 * means there was an error in the evote protocol. 
 * @author joshualee
 *
 */
public class EVoteInvalidResult extends Exception {	
	private static final long serialVersionUID = 1L;

	public EVoteInvalidResult(String msg)	 {
		super(msg);
	}

}
