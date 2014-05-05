package edu.harvard.cs262.crypto.cipher;
/**
 * This is the Key object. It contains both the private and public keys of a user.
 * If no public key is specified, then it is a pure private key. If a public key is specified,
 * then it is a private key public key pair that can be used for public key encryption schemes.
 *
 * @author Holly Anderson, Joshua Lee, and Tracy Lu
 */
public class CryptoKey {
	/** 
	 *	Bits specifies how many bits we use when generating a random number.
	 *  It is a security parameter that allows use to determine how secure we want
	 *  our random numbers to be.
	 */
	private int bits;
	
	private Object priv; // the private key
	private Object pub; // the public key
	
	public CryptoKey() {
		setBits(31);
		priv = null;
		pub = null;
	}
	
	public CryptoKey(Object priv, int bits) {
		this.setBits(bits);
		this.priv = priv;
		pub = null;
	}
	
	public CryptoKey(Object priv, Object pub, int bits) {
		this.setBits(bits);
		this.priv = priv;
		this.pub = pub;
	}

	public Object getPrivate() {
		return priv;
	}

	public void setPrivate(Object priv) {
		this.priv = priv;
	}

	public Object getPublic() {
		return pub;
	}

	public void setPublic(Object pub) {
		this.pub = pub;
	}

	public int getBits() {
		return bits;
	}

	public void setBits(int bits) {
		this.bits = bits;
	}
}
