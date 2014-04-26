package edu.harvard.cs262.tests;

import java.math.BigInteger;

public class Sandbox {
	public static void main(String args[]) {
		BigInteger g = BigInteger.valueOf(2341L);
		BigInteger p = BigInteger.valueOf(31123L);
		
		
		BigInteger sk_i = BigInteger.valueOf(20546L);
		BigInteger pk_i = g.modPow(sk_i, p);
		
		BigInteger c1 = BigInteger.valueOf(25777L);
		
//		System.out.println(c1.modPow(sk_i, p));
		
		System.out.println(g.modPow(BigInteger.valueOf(2L), p));
		
	}
}
