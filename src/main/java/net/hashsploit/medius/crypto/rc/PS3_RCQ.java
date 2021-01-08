package net.hashsploit.medius.crypto.rc;

import net.hashsploit.medius.crypto.CipherContext;
import net.hashsploit.medius.crypto.ICipher;
import net.hashsploit.medius.crypto.SCERTDecryptedData;
import net.hashsploit.medius.crypto.SCERTEncryptedData;
import net.hashsploit.medius.crypto.Utils;
import net.hashsploit.medius.crypto.hash.SHA1;

/**
 * PlayStation 3's custom RC Medius implementation 
 * @author hashsploit
 */
public class PS3_RCQ implements ICipher {
	
	private byte[] key = null;
	private CipherContext context;
	
	public PS3_RCQ(byte[] key, CipherContext context) {
		this.context = context;
		setKey(key);
	}
	
	public void setKey(byte[] key) {
		setKey(key);
	}

	@Override
	public SCERTDecryptedData decrypt(byte[] data, byte[] hash) {
		
        if (key == null) {
            return null;
        }

        byte[] plain = new byte[data.length];
        System.arraycopy(data, 0, plain, 0, plain.length);

        // Check if empty hash
        // If hash is 0, the data is already in plaintext
        if (hash[0] == 0 && hash[1] == 0 && hash[2] == 0 && (hash[3] & 0x1F) == 0) {
        	return new SCERTDecryptedData(plain, true);
        }

        // IV
        byte[] iv = new byte[(byte)0x10];
        short[] seed = new short[4];
        System.arraycopy(key, 0, iv, 0, (byte) 0x10);
        
        // FIXME: missing

        return null;
	}

	@Override
	public SCERTEncryptedData encrypt(byte[] data) {
		return null;
	}

	
	
	
	
	
	
	
	
	
	
	
	/**
	 * Iterate through buffer and flip endianness of each 4 byte word.
	 * @param input
	 */
	protected static void flipWords(byte[] input) {
		for (int i = 0; i < input.length; i += 4) {
			byte temp = input[i + 0];
			input[i + 0] = input[i + 3];
			input[i + 3] = temp;
			temp = input[i + 1];
			input[i + 1] = input[i + 2];
			input[i + 2] = temp;
		}
	}
	
	 protected static void rcPass(byte[] input, char[] iv, boolean sign)
     {
		 char r0 = (char) 0x00000000;
		 char r3 = (char) 0x5B3AA654;
		 char r5 = (char) 0x75970A4D;
		 char r6 = (char) 0x00000000;

         
         int newLength = (input.length % 4 != 0) ? (input.length + (4 - (input.length % 4))) : input.length;
         byte[] buffer = new byte[newLength];
         
         System.arraycopy(input, 0, buffer, 0, input.length);
         flipWords(buffer);

         // B5A0559C 88AA4C20 013D2CC7 CB2DE2B6
         char r16 = iv[0];
         char r17 = iv[1];
         char r18 = iv[2];
         char r19 = iv[3];

         for (int i = 0; i < input.length; i += 4)
         {
             r19 ^= r3;
             r18 += r16;
             r18 += r19;
             r18 = (char) ((r18 << 7) | (r18 >> (32 - 7)));
             r17 += r19;
             r17 += r18;
             r18 ^= r5;
             r17 = (char) ((r17 << 11) | (r17 >> (32 - 11)));
             r16 += r18;
             r16 += r17;
             r16 = (char) ((r16 >> 15) | (r16 << (32 - 15)));
             r0 = (char) (r16 & r17);
             r17 = (char) ~r17;
             r6 = (char) (r18 & r17);
             r0 |= r6;
             r19 += r0;
             r16 = (char) ~r16;

             r0 = (char)((buffer[i + 0] << 24) | (buffer[i + 1] << 16) | (buffer[i + 2] << 8) | (buffer[i + 3] << 0));
             r19 ^= r0;

             if (sign)
             {
            	 // FIXME find alternative
                 //byte[] r19_b = BitConverter.GetBytes(r19);
            	 byte[] r19_b = new byte[4];
                 buffer[i + 0] = r19_b[0];
                 buffer[i + 1] = r19_b[1];
                 buffer[i + 2] = r19_b[2];
                 buffer[i + 3] = r19_b[3];
             }
         }

         iv[0] = r16;
         iv[1] = r17;
         iv[2] = r18;
         iv[3] = r19;

         // Copy signed buffer back into input
         // This can be moved into the loop at some point
         if (sign) {
             for (int i = 0; i < input.length; ++i) {
                 input[i] = buffer[i];
             }
         }
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
		if (obj instanceof PS3_RCQ) {
			PS3_RCQ rc = (PS3_RCQ) obj;
			return rc.equals(this);
		}
		return super.equals(obj);
	}
	
	public boolean equals(PS3_RCQ b) {
		return b.context == this.context && Utils.sequenceEquals(b.key, this.key);
	}

	@Override
	public String toString() {
		return "PS3_RC(" + context + ", " + Utils.bytesToHex(key) + ")";
	}
	
}
