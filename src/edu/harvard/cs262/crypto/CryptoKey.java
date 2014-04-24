package edu.harvard.cs262.crypto;

public class CryptoKey {
	private int bits;
	private Object priv;
	private Object pub;
	
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
