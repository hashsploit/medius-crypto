package net.hashsploit.medius.crypto.hash;

import org.bouncycastle.crypto.digests.SHA1Digest;

import net.hashsploit.medius.crypto.CipherContext;

public class SHA1 {

	// Prevent instantiation
	private SHA1() {}
	
	public static byte[] hash(byte[] input, CipherContext context) {
		return hash(input, 0, input.length, 0, (byte)context.id);
	}

	public static byte[] hash(byte[] input, int inOff, int length, int outOff, byte encryptionType) {
		byte[] result = new byte[20];
		byte[] output = new byte[4];

		// Compute sha1 hash
		SHA1Digest digest = new SHA1Digest();
		digest.update(input, inOff, length);
		digest.doFinal(result, 0);

		// Inject context inter highest 3 bits
		result[3] = (byte) ((result[3] & (byte) 0x1F) | ((encryptionType & 7) << 5));

		System.arraycopy(result, 0, output, outOff, 4);

		return output;
	}

}
