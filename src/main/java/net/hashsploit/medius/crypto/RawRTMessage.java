package net.hashsploit.medius.crypto;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class RawRTMessage {
	
	private final byte id; // 1 byte
	private final short length; // 2 bytes
	private final byte[] hash; // 4 bytes
	private final byte[] payload;
	
	/**
	 * Represents a single raw data packet from a SCERT client.
	 * @param id
	 * @param checksum
	 * @param payload
	 */
	public RawRTMessage(byte id, short length, byte[] hash, byte[] payload) {
		this.id = id;
		this.hash = hash;
		this.length = length;
		this.payload = payload;
		
		if (length != payload.length) {
			throw new IllegalStateException("RT length provided does not match the payload length.");
		}
		
	}
	
	/**
	 * Automatically attempt to parse a single SCERT message into the proper components.
	 * @param data
	 */
	public RawRTMessage(byte[] data) {
		
		if (data.length < 3) {
			throw new IllegalArgumentException("Payload is too short to be a valid RT Message.");
		}
		
		ByteBuffer buffer = ByteBuffer.allocate(data.length);
		
		buffer.put(data);
		buffer.flip();
		
		buffer.order(ByteOrder.LITTLE_ENDIAN);
		this.id = buffer.get();
		this.length = buffer.getShort();
		
		// If this message is encrypted.
		if (id >= 0x80) {
			// The hash is 4 bytes
			this.hash = new byte[] {
				buffer.get(), buffer.get(),
				buffer.get(), buffer.get()
			};
		} else {
			this.hash = null;
		}
		
		this.payload = new byte[length];
		buffer.get(payload);
	}
	
	/**
	 * Get the packet type id.
	 * @return
	 */
	public byte getId() {
		return id;
	}
	
	/**
	 * Get the message length.
	 * @return
	 */
	public short getLength() {
		return length;
	}
	
	/**
	 * Get the crypto hash of this message.
	 * Returns null if the hash does not exist.
	 */
	public byte[] getHash() {
		return hash;
	}
	
	/**
	 * Get the raw payload itself.
	 * @return
	 */
	public byte[] getPayload() {
		return payload;
	}
	
	/**
	 * Check if this Raw RT Message is encrypted.
	 * @return
	 */
	public boolean isEncrypted() {
		return hash != null || id >= 0x80;
	}
	
	/**
	 * Get the full representation of the data.
	 * @return
	 */
	public byte[] toBytes() {
		ByteBuffer buffer = ByteBuffer.allocate(1 + 2 + (isEncrypted() ? 4 : 0) + length); // Payload length + 3 for RT ID and RT length (and +4 if the hash is not null)
		
		buffer.order(ByteOrder.LITTLE_ENDIAN);
		
		buffer.put(id);
		buffer.putShort(length);
		
		if (isEncrypted()) {
			buffer.put(hash);
		}
		
		buffer.put(payload);
		
		buffer.flip();
		return buffer.array();
	}
	
}
