package net.hashsploit.medius.crypto;

import java.math.BigInteger;
import java.nio.charset.Charset;

import net.hashsploit.medius.crypto.CipherContext;
import net.hashsploit.medius.crypto.SCERTDecryptedData;
import net.hashsploit.medius.crypto.SCERTEncryptedData;
import net.hashsploit.medius.crypto.Utils;
import net.hashsploit.medius.crypto.rc.PS2_RC4;
import net.hashsploit.medius.crypto.rsa.PS2_RSA;

public class Test {
	
	private static final BigInteger N = new BigInteger("101177020773116032450768434219907665711628442914109359705930212851485814671757");
	private static final BigInteger E = new BigInteger("101959470976625878182337603500729946859798449583099010462249380230433894289641");
	private static final BigInteger D = new BigInteger("4854567300243763614870687120476899445974505675147434999327174747312047455575182761195687859800492317495944895566174677168271650454805328075020357360662513");
	
	public static void main(String[] args) {
		print("Running Medius Encrypt/Decrypt tests ...");
		
		print("#### Testing PS2 Textboook RSA encryption/decryption");
		ps2_rsa_test();
		
		print("#### Testing PS2 RC4 encryption/decryption");
		ps2_rc4_test();
		
	}
	
	
	private static void ps2_rsa_test() {
		
		String message = "Hello this is a plaintext message!";
		
		byte[] messageBytes = message.getBytes();
		PS2_RSA rsa = new PS2_RSA(N, E, D);
		SCERTEncryptedData encryptedMessage = rsa.encrypt(messageBytes);
		byte[] hash = encryptedMessage.getHash();
		
		print("RSA -> message: " + message);
		print("RSA -> messageBytes: " + Utils.bytesToHex(messageBytes));
		print("RSA -> encryptedMessageBytes: " + Utils.bytesToHex(encryptedMessage.getData()));
		
		SCERTDecryptedData decryptedMessage = rsa.decrypt(encryptedMessage.getData(), hash);
		
		print("RSA -> decryptedMessageBytes: " + Utils.bytesToHex(decryptedMessage.getData()));
		print("RSA -> decryptedMessage: " + new String(decryptedMessage.getData()));
		
	}
	
	
	private static void ps2_rc4_test() {
		
		byte[] key = new byte[] {
			0x42, 0x42, 0x42, 0x42,  0x42, 0x42, 0x42, 0x42,
			0x42, 0x42, 0x42, 0x42,  0x42, 0x42, 0x42, 0x42,
			0x42, 0x42, 0x42, 0x42,  0x42, 0x42, 0x42, 0x42,
			0x42, 0x42, 0x42, 0x42,  0x42, 0x42, 0x42, 0x42,
			0x42, 0x42, 0x42, 0x42,  0x42, 0x42, 0x42, 0x42,
			0x42, 0x42, 0x42, 0x42,  0x42, 0x42, 0x42, 0x42,
			0x42, 0x42, 0x42, 0x42,  0x42, 0x42, 0x42, 0x42,
			0x42, 0x42, 0x42, 0x42,  0x42, 0x42, 0x42, 0x42
		};
		
		byte[] data = "Hello World!".getBytes(Charset.forName("UTF-8"));
		
		print("Key: " + Utils.bytesToHex(key));
		print("Data: " + Utils.bytesToHex(data));
		
		for (CipherContext context : CipherContext.values()) {
			PS2_RC4 rc = new PS2_RC4(key, context);
			SCERTEncryptedData encrypted = rc.encrypt(data);
			print("Encrypted status: " + encrypted.isSuccessful());
			print("Encrypted data: " + Utils.bytesToHex(encrypted.getData()));
			print("Encryption hash: " + Utils.bytesToHex(encrypted.getHash()));
			
			SCERTDecryptedData decrypted = rc.decrypt(encrypted.getData(), encrypted.getHash());
			print("Decrypted status: " + encrypted.isSuccessful());
			print("Decrypted data: " + Utils.bytesToHex(decrypted.getData()));
			print("----");
		}
	}
	
	private static void print(String s) {
		System.out.println(s);
	}
	
}
