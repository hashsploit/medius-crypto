package net.hashsploit.medius.crypto;

public class SCERTEncryptedData {
	
	private byte[] data;
	private byte[] hash;
	private boolean success;
	
	public SCERTEncryptedData(final byte[] data, final byte[] hash, boolean status) {
		this.data = data;
		this.hash = hash;
		this.success = status;
	}
	
	/**
	 * Get the encrypted data.
	 * @return
	 */
	public byte[] getData() {
		return data;
	}
	
	/**
	 * Get the hash used.
	 * @return
	 */
	public byte[] getHash() {
		return hash;
	}
	
	/**
	 * Returns true if encryption was successful.
	 * @return
	 */
	public boolean isSuccessful() {
		return success;
	}
	
}