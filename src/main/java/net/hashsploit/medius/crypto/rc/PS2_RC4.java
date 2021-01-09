package net.hashsploit.medius.crypto.rc;

import net.hashsploit.medius.crypto.CipherContext;
import net.hashsploit.medius.crypto.ICipher;
import net.hashsploit.medius.crypto.SCERTDecryptedData;
import net.hashsploit.medius.crypto.SCERTEncryptedData;
import net.hashsploit.medius.crypto.Utils;
import net.hashsploit.medius.crypto.hash.SHA1;

/**
 * PlayStation 2's custom RC4 Medius implementation
 * 
 * @author hashsploit
 */
public class PS2_RC4 implements ICipher {

	private static final int STATE_LENGTH = 256;

	private final byte[] workingKey;
	private CipherContext context;
	
	private class RC4State {
		public byte[] engineState;
		public int x;
		public int y;
	}

	/**
	 * Initialize crypto with a 512-bit key
	 * 
	 * @param key
	 * @param context
	 */
	public PS2_RC4(byte[] key, CipherContext context) {
		this.context = context;
		workingKey = key;
	}

	private void setKey(RC4State state, byte[] key, byte[] hash) {
		
		state.x = 0;
		state.y = 0;

		int keyIndex = 0;
		int li = 0;
		int cipherIndex = 0;
		int idIndex = 0;

		// Initialize engine state
		if (state.engineState == null) {
			state.engineState = new byte[STATE_LENGTH];
		}

		// reset the state of the engine
		// Normally this initializes values 0,1..254,255 but this RC4 implemenation does it in reverse.
		for (int i = 0; i < STATE_LENGTH; i++) {
			state.engineState[i] = (byte) ((STATE_LENGTH - 1) - i);
		}

		if (hash != null && hash.length == 4) {
			// Apply hash
			do {
				int v1 = hash[idIndex];
				idIndex = (idIndex + 1) & 3;

				byte temp = state.engineState[cipherIndex];
				v1 += li;
				li = (temp + v1) & 0xFF;

				state.engineState[cipherIndex] = state.engineState[li];
				state.engineState[li] = temp;

				cipherIndex = (cipherIndex + 5) & 0xFF;

			} while (cipherIndex != 0);

			// Reset
			keyIndex = 0;
			li = 0;
			cipherIndex = 0;
			idIndex = 0;
		}

		// Apply key
		do {
			int keyByte = key[keyIndex];
			keyByte += li;
			keyIndex += 1;
			keyIndex &= 0x3F;

			int cipherByte = state.engineState[cipherIndex];
			byte cipherValue = (byte) (cipherByte & 0xFF);

			cipherByte += keyByte;
			li = cipherByte & 0xFF;

			byte t0 = state.engineState[li];
			state.engineState[cipherIndex] = t0;
			state.engineState[li] = cipherValue;

			cipherIndex += 3;
			cipherIndex &= 0xFF;
		} while (cipherIndex != 0);
	}

	private void _decrypt(RC4State state, byte[] input, int inOff, int length, byte[] output, int outOff) {

		for (int i = 0; i < length; ++i) {
			state.y = (state.y + 5) & 0xFF;

			int v0 = state.engineState[state.y];
			byte a2 = (byte) (v0 & 0xFF);
			v0 += state.x;
			state.x = (int) (v0 & 0xFF);

			v0 = state.engineState[state.x];
			state.engineState[state.y] = (byte) (v0 & 0xFF);
			state.engineState[state.x] = a2;

			byte a0 = input[i + inOff];

			v0 += a2;
			v0 &= 0xFF;
			int v1 = state.engineState[v0] & 0xFF;

			a0 ^= (byte) v1;
			output[i + outOff] = (byte) (a0 & 0xFF);
			
			v1 = state.engineState[a0 & 0xFF] + state.x;
			state.x = v1 & 0xFF;
		}
	}

	@Override
	public SCERTDecryptedData decrypt(byte[] data, byte[] hash) {

		byte[] plain = new byte[data.length];
		RC4State state = new RC4State();

		// Check if empty hash
		// If hash is 0, the data is already in plaintext
		if (hash[0] == 0 && hash[1] == 0 && hash[2] == 0 && (hash[3] & 0x1F) == 0) {
			System.arraycopy(data, 0, plain, 0, data.length);
			return new SCERTDecryptedData(plain, true);
		}

		// Set seed
		setKey(state, workingKey, hash);

		_decrypt(state, data, 0, data.length, plain, 0);
		
		final byte[] chkHash = hash(plain);
		return new SCERTDecryptedData(plain, Utils.sequenceEquals(hash, chkHash));
	}

	private void _encrypt(RC4State state, byte[] input, int inOff, int length, byte[] output, int outOff) {

		for (int i = 0; i < length; ++i) {
			state.x = (state.x + 5) & 0xFF;
			state.y = (state.y + state.engineState[state.x]) & 0xFF;

			// Swap
			final byte temp = state.engineState[state.x];
			state.engineState[state.x] = state.engineState[state.y];
			state.engineState[state.y] = temp;

			// Xor
			output[i + outOff] = (byte) ((input[i + inOff] & 0xFF) ^ (state.engineState[((state.engineState[state.x]&0xFF) + (state.engineState[state.y]&0xFF)) & 0xFF]));
			
			state.y = (state.engineState[input[i + inOff] & 0xFF] + state.y) & 0xFF;
		}
	}

	/**
	 * Encrypt data using the last key provided
	 */
	@Override
	public SCERTEncryptedData encrypt(byte[] data) {

		RC4State state = new RC4State();
		
		// Set seed
		byte[] hash = SHA1.hash(data, context);
		setKey(state, workingKey, hash);

		byte[] cipher = new byte[data.length];
		_encrypt(state, data, 0, data.length, cipher, 0);

		return new SCERTEncryptedData(cipher, hash, true);
	}

	@Override
	public CipherContext getContext() {
		return context;
	}

	protected void setContext(CipherContext cipherContext) {
		this.context = cipherContext;
	}

	public byte[] hash(byte[] input) {
		return SHA1.hash(input, context);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof PS2_RC4) {
			PS2_RC4 rc = (PS2_RC4) obj;
			return rc.equals(this);
		}
		return super.equals(obj);
	}

	public boolean equals(PS2_RC4 b) {
		return b.context == this.context && Utils.sequenceEquals(b.workingKey, this.workingKey);
	}

	@Override
	public String toString() {
		return "PS2_RC4(" + context + ", " + Utils.bytesToHex(workingKey) + ")";
	}

}
