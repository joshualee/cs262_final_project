package edu.harvard.cs262.crypto.exception;

/**
 * Thrown when the result of the evote is not de-codeable. This most likely
 * means there was an error in the e-vote protocol. 
 *
 * @author Holly Anderson, Joshua Lee, and Tracy Lu
 */
public class EVoteInvalidResult extends Exception {	
	private static final long serialVersionUID = 1L;

	public EVoteInvalidResult(String msg)	 {
		super(msg);
	}
}
