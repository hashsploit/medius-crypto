package net.hashsploit.medius;

/**
 * The highest 3 bits of the hash.
    Denotes which key is used to encrypt/decrypt the respective message.
 * @author hashsploit
 */
public enum CipherContext {
	
	ID_00(0x00),
	
	RC_SERVER_SESSION(0x01),
	
	ID_02(0x02),
	
	RC_CLIENT_SESSION(0x03),
	
	ID_04(0x04),
	
	ID_05(0x05),
	
	ID_06(0x06),
	
	RSA_AUTH(0x07);
	
	public final byte id;
	
	private CipherContext(int id) {
		this.id = (byte) id;
	}
	
	
}
