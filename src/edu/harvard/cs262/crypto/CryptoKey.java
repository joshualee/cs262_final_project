package edu.harvard.cs262.crypto;

public class CryptoKey {
	
	private Object priv;
	private Object pub;
	
	public CryptoKey() {
		priv = null;
		pub = null;
	}
	
	public CryptoKey(Object priv) {
		this.priv = priv;
		pub = null;
	}
	
	public CryptoKey(Object priv, Object pub) {
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

}
