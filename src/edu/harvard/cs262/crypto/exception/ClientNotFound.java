package edu.harvard.cs262.crypto.exception;

/**
 * Exception for when a client does not exist
 *
 * @author Holly Anderson, Joshua Lee, and Tracy Lu
 */
public class ClientNotFound extends Exception {
	private static final long serialVersionUID = 1L;

	public ClientNotFound(String msg) {
		super(msg);
	}
}