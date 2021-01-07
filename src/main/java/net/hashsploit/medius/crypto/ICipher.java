package net.hashsploit.medius.crypto;

public interface ICipher {
	
	/**
	 * Cipher context
	 * @return
	 */
	public CipherContext getContext();
	
	/**
	 * Decrypts the cipher text with the hash.
	 * @param input
	 * @param hash
	 * @return
	 */
	SCERTDecryptedData decrypt(byte[] input, byte[] hash);
	
	/**
	 * Encrypts the given input buffer and returns the cipher and hash.
	 * @param plain
	 * @return
	 */
	SCERTEncryptedData encrypt(byte[] plain);
	
	/**
	 * Computes the hash of the given input buffer.
	 * @param input
	 * @return
	 */
	byte[] hash(byte[] input);
	
}
