package net.hashsploit.medius.crypto;

public class SCERTDecryptedData {
	
	private byte[] plain;
	private boolean success;
	
	public SCERTDecryptedData(final byte[] data, boolean success) {
		this.plain = data;
		this.success = success;
	}
	
	/**
	 * Get the decrypted plaintext data.
	 * @return
	 */
	public byte[] getData() {
		return plain;
	}
	
	/**
	 * Returns true if encryption was successful.
	 * @return
	 */
	public boolean isSuccessful() {
		return success;
	}
	
}
