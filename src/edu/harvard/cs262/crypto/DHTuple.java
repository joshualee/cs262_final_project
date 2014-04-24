package edu.harvard.cs262.crypto;

import java.math.BigInteger;

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
