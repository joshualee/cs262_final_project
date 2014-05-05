package edu.harvard.cs262.crypto.cipher;

import java.math.BigInteger;
/**
 * This holds the information necessary for Diffie Hellman key exchange.
 *
 * @author Holly Anderson, Joshua Lee, and Tracy Lu
 */
public class DHTuple {
	public BigInteger p; // public parameter
	public BigInteger g; // public parameter
	public BigInteger xhat; // generated during key exchange
	
	public DHTuple(BigInteger p, BigInteger g, BigInteger xhat) {
		this.p = p;
		this.g = g;
		this.xhat = xhat;
	}
}
