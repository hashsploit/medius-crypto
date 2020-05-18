package net.hashsploit.medius;

public class MediusDecryptedData {
	
	private byte[] plain;
	private boolean success;
	
	public MediusDecryptedData(final byte[] plain, boolean success) {
		this.plain = plain;
		this.success = success;
	}
	
	public byte[] getPlain() {
		return plain;
	}
	
	/**
	 * Returns true if encryption was successful
	 * @return
	 */
	public boolean isSuccessful() {
		return success;
	}
	
}
