package edu.harvard.cs262.crypto;

public class MathHelpers {
	
	/**
	 * Integer power function, adapted from:
	 * http://stackoverflow.com/questions/101439/
	 * @param base
	 * @param exp
	 * @return base^exp
	 */
	public static int ipow(int base, int exp) {
	    int result = 1;
	    while (exp != 0) {
	    	
	        if ((exp & 1) != 0)
	            result = (result * base);
	        exp >>= 1;
	        base *= base;
	    }

	    return result;
	}
	
	public static int ipowmod(int base, int exp, int p) {
	    int result = 1;
	    while (exp != 0) {
	    	
	        if ((exp & 1) != 0)
	            result = (result * base) % p;
	        exp >>= 1;
	        base *= base;
	    }

	    return result;
	}
	
	/**
	 * @return (a^b mod c)
	 */
	public static int expmod(int a, int b, int c) {
		return ipowmod(a, b, c);
	}


}
