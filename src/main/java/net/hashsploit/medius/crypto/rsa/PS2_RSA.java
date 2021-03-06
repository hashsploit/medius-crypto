package net.hashsploit.medius.crypto.rsa;

import java.math.BigInteger;
import java.util.Arrays;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;

import net.hashsploit.medius.crypto.CipherContext;
import net.hashsploit.medius.crypto.ICipher;
import net.hashsploit.medius.crypto.SCERTDecryptedData;
import net.hashsploit.medius.crypto.SCERTEncryptedData;
import net.hashsploit.medius.crypto.Utils;
import net.hashsploit.medius.crypto.hash.SHA1;

/**
 * Textbook RSA implementation
 * 
 * n = p * q
 * 
 * e = public exponent d = private exponent
 * 
 * Encrypt: c = m^e * mod(n)
 * 
 * Decrypt: m = c^d * mod(n)
 * 
 * 
 * @author hashsploit
 */
public class PS2_RSA implements ICipher {

	private static final BigInteger mediusGlobalKeyN;
	private static final BigInteger mediusGlobalKeyE;
	private static final BigInteger mediusGlobalKeyD;
	private CipherContext context;
	private final BigInteger n;
	private final BigInteger e;
	private BigInteger d;

	/**
	 * Create a new RSA key-pair.
	 * 
	 * @param n = p * q
	 * @param e = public exponent
	 * @param d = private exponent
	 */
	public PS2_RSA(BigInteger n, BigInteger e, BigInteger d) {
		this.n = n;
		this.e = e;
		this.d = d;
	}
	
	/**
	 * Generate a new RSA encryption key.
	 * @param n
	 * @param e
	 */
	public PS2_RSA(BigInteger n, BigInteger e) {
		this(n, e, null);
	}
	
	/**
	 * Generate the RSA key-pair to encrypt and decrypt messages from the SCE-RT GLOBAL key.
	 */
	public PS2_RSA() {
		this(mediusGlobalKeyN, mediusGlobalKeyE, mediusGlobalKeyD);
	}

	private BigInteger _encrypt(BigInteger m) {
		return m.modPow(e, n);
	}

	private BigInteger _decrypt(BigInteger c) {
		return c.modPow(d, n);
	}

	@Override
	public SCERTDecryptedData decrypt(byte[] input, byte[] hash) {
		input = Utils.flipByteArray(input);
		BigInteger plainBigInt = _decrypt(new BigInteger(1, input));

		byte[] plain = plainBigInt.toByteArray();
		plain = Utils.flipByteArray(plain);

		// Sometimes has an extra zero at the end
		if (plain.length != input.length) {
			plain = Arrays.copyOf(plain, input.length);
		}
		
		byte[] ourHash = hash(plain);

		if (Utils.sequenceEquals(ourHash, hash)) {
			return new SCERTDecryptedData(plain, true);
		}

		// Handle case where message > n
		plainBigInt = plainBigInt.add(n);
		plain = plainBigInt.toByteArray();
		plain = Utils.flipByteArray(plain);
		
		// Sometimes has an extra zero at the end
		if (plain.length != input.length) {
			plain = Arrays.copyOf(plain, input.length);
		}
		
		ourHash = hash(plain);

		return new SCERTDecryptedData(plain, Utils.sequenceEquals(ourHash, hash));
	}

	@Override
	public SCERTEncryptedData encrypt(byte[] input) {
		byte[] hash = hash(input);
		input = Utils.flipByteArray(input);
		byte[] cipher = _encrypt(new BigInteger(1, input)).toByteArray();
		cipher = Utils.flipByteArray(cipher);
		// Sometimes has an extra zero at the end
		if (cipher.length != input.length) {
			cipher = Arrays.copyOf(cipher, input.length);
		}
		return new SCERTEncryptedData(cipher, hash, true);
	}

	public void setContext(CipherContext context) {
		this.context = context;
	}

	@Override
	public CipherContext getContext() {
		return context;
	}

	@Override
	public byte[] hash(byte[] input) {
		return SHA1.hash(input, context);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof PS2_RSA) {
			PS2_RSA rsa = (PS2_RSA) obj;
			return rsa.equals(this);
		}
		return super.equals(obj);
	}

	/**
	 * Get n (n = p * q) n = p * q
	 * 
	 * @return
	 */
	public BigInteger getN() {
		return n;
	}

	/**
	 * Get e (public exponent)
	 * 
	 * @return
	 */
	public BigInteger getE() {
		return e;
	}

	/**
	 * Get d (private exponent)
	 * 
	 * @return
	 */
	public BigInteger getD() {
		return d;
	}
	
	/**
	 * Do this once.
	 */
	static {
		// Load key from file
		JSONTokener tokener = new JSONTokener(PS2_RSA.class.getResourceAsStream("/keys/ps2.json"));
		JSONArray jsonArray = new JSONArray(tokener);
		
		// Get the GLOBAL MEDIUS KEY
		JSONObject o = (JSONObject) jsonArray.get(0);

		mediusGlobalKeyN = new BigInteger(o.getString("n"), 10);
		mediusGlobalKeyE = new BigInteger(o.getString("e"), 10);
		mediusGlobalKeyD = new BigInteger(o.getString("d"), 10);
	}

}
