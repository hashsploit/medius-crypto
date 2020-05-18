package net.hashsploit.medius;

public class MediusEncryptedData {
	
	private byte[] cipher;
	private byte[] hash;
	private boolean success;
	
	public MediusEncryptedData(final byte[] cipher, final byte[] hash, boolean status) {
		this.cipher = cipher;
		this.hash = hash;
		this.success = status;
	}
	
	public byte[] getCipher() {
		return cipher;
	}
	
	public byte[] getHash() {
		return hash;
	}
	
	/**
	 * Returns true if encryption was successful
	 * @return
	 */
	public boolean isSuccessful() {
		return success;
	}
	
}