package net.hashsploit.medius;

import java.nio.charset.Charset;

import net.hashsploit.medius.hash.SHA1;
import net.hashsploit.medius.rc.PS2_RC4;

public class Test {
	
	
	public static void main(String[] args) {
		print("Running Java Medius Encrypt/Decrypt tests ...");
		
		sha1Test();
		print("");
		
		ps2rc4Test();
		print("");
		
	}
	
	private static void sha1Test() {
		header("SHA1 TEST");
		
		byte[] data = new byte[] {
			1, 1, 1, 1, 1,
			1, 1, 1, 1, 1,
			1, 1, 1, 1, 1,
			1, 1, (byte)255, 1, 1
		};
		
		print("Data: " + Utils.bytesToString(data));
		
		for (CipherContext context : CipherContext.values()) {
			StringBuilder sb = new StringBuilder();
			sb.append("Hashed CipherContext(");
			sb.append(Utils.byteToString(context.id)).append("/").append(context.name()).append("): ");
			sb.append(Utils.bytesToString(SHA1.hash(data, context)));
			print(sb.toString());
			
		}	
	}
	
	private static void ps2rc4Test() {
		header("PS2 RC4 TEST");
		
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
		
		print("Key: " + Utils.bytesToString(key));
		print("Data: " + Utils.bytesToString(data));
		
		for (CipherContext context : CipherContext.values()) {
			PS2_RC4 rc = new PS2_RC4(key, context);
			MediusEncryptedData encrypted = rc.encrypt(data);
			print("Encrypted status: " + encrypted.isSuccessful());
			print("Encrypted data: " + Utils.bytesToString(encrypted.getCipher()));
			print("Encryption hash: " + Utils.bytesToString(encrypted.getHash()));
			
			MediusDecryptedData decrypted = rc.decrypt(encrypted.getCipher(), encrypted.getHash());
			print("Decrypted status: " + encrypted.isSuccessful());
			print("Decrypted data: " + Utils.bytesToString(decrypted.getPlain()));
			print("----");
		}
		
	}
	
	private static void header(String s) {
		print("==== " + s + " ====");
	}
	
	private static void print(String s) {
		System.out.println(s);
	}
	
}
