package net.hashsploit.medius.rsa;

import java.math.BigInteger;

import net.hashsploit.medius.hash.SHA1;

public class PS3_RSA extends PS2_RSA {
	
	public PS3_RSA(BigInteger n, BigInteger e, BigInteger d) {
		super(n, e, d);
	}
	
	@Override
	public byte[] hash(byte[] input) {
		return SHA1.hash(input, super.getContext());
	}
	
}
