package edu.harvard.cs262.crypto;

/**
 * Thrown when the result of the evote is not decodeable. This most likely
 * means there was an error in the evote protocol. 
 * @author joshualee
 *
 */
public class EVoteInvalidResult extends Exception {
	public String msg;
	
	public EVoteInvalidResult(String errorMsg)	 {
		msg = errorMsg;
	}

}
