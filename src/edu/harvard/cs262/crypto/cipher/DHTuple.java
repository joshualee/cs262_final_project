package edu.harvard.cs262.crypto.cipher;

import java.math.BigInteger;
/**
 * This holds the information necessary for Diffie Hellman key exchange.
 *
 * @author Joshua Lee and Tracy Lu
 */
public class DHTuple {
	public BigInteger p;
	public BigInteger g;
	public BigInteger xhat;
	
	public DHTuple(BigInteger p, BigInteger g, BigInteger xhat) {
		this.p = p;
		this.g = g;
		this.xhat = xhat;
	}
}
