package net.hashsploit.medius.crypto;

import java.math.BigInteger;

public class InternalRsaKey {
	
	private BigInteger n;
	private BigInteger e;
	private BigInteger d;
	
	public InternalRsaKey(final BigInteger n, final BigInteger e, final BigInteger d) {
		this.n = n;
		this.e = e;
		this.d = d;
	}
	
	/**
	 * Get n (n = p * q)
	 * n = p * q
	 * @return
	 */
	public BigInteger getN() {
		return n;
	}
	
	/**
	 * Set n (n = p * q)
	 * @param n
	 */
	protected void setN(BigInteger n) {
		this.n = n;
	}
	
	/**
	 * Get e (public exponent)
	 * @return
	 */
	public BigInteger getE() {
		return e;
	}
	
	/**
	 * Set e (public exponent)
	 * @param e
	 */
	protected void setE(BigInteger e) {
		this.e = e;
	}
	
	/**
	 * Get d (private exponent)
	 * @return
	 */
	public BigInteger getD() {
		return d;
	}
	
	/**
	 * Set d (private exponent)
	 * @param d
	 */
	protected void setD(BigInteger d) {
		this.d = d;
	}
	
}
