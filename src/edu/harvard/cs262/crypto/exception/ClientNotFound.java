package edu.harvard.cs262.crypto.exception;

public class ClientNotFound extends Exception {
	private static final long serialVersionUID = 1L;

	public ClientNotFound(String msg) {
		super(msg);
	}
}