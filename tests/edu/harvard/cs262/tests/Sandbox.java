package edu.harvard.cs262.tests;

import java.math.BigInteger;
import java.sql.Timestamp;

import edu.harvard.cs262.crypto.VPrint;

public class Sandbox {
	public static void main(String args[]) {
		BigInteger g = BigInteger.valueOf(2341L);
		BigInteger p = BigInteger.valueOf(31123L);
		
		BigInteger sk_i = BigInteger.valueOf(20546L);
		BigInteger pk_i = g.modPow(sk_i, p);
		
		BigInteger c1 = BigInteger.valueOf(25777L);
		
//		System.out.println(c1.modPow(sk_i, p));
		
//		System.out.println(g.modPow(BigInteger.valueOf(2L), p));
		
//		VPrint printer = new VPrint(VPrint.ALL, "sandbox.log");
//		printer.print(printer.DEBUG, "test debug %s", "1");
//		printer.print(printer.WARN, "test WARN %s %s", "1", "2");
//		printer.print(printer.NORMAL, "test normal");
		
		java.util.Date date= new java.util.Date();
		System.out.println(new Timestamp(date.getTime()));
	}
}
