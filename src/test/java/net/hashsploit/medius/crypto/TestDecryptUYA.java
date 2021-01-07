package net.hashsploit.medius.crypto;

import java.math.BigInteger;

import net.hashsploit.medius.crypto.rsa.PS2_RSA;

public class TestDecryptUYA {

	private static final BigInteger N = new BigInteger("101177020773116032450768434219907665711628442914109359705930212851485814671757");
	private static final BigInteger E = new BigInteger("101959470976625878182337603500729946859798449583099010462249380230433894289641");
	private static final BigInteger D = new BigInteger("4854567300243763614870687120476899445974505675147434999327174747312047455575182761195687859800492317495944895566174677168271650454805328075020357360662513");

	private BigInteger rsaKey;

	public static void main(String[] args) {
		print("Running UYA Medius Encrypt/Decrypt tests ...");

		// 0x12 CLIENT_CRYPTKEY_PUBLIC [RSA_AUTH]
		byte[] client_message_01 = Utils.hexStringToByteArray("924000f4f87af73425c89a6da9ddebaba83ca6e6b4726def512300deea43d58f22503faf9c5296107ca4bea9578aae4968062073c624a807ad44d254298d58b63cda3be4338c57");

		// 0x13 SERVER_CRYPTKEY_PEER [RSA_AUTH]
		byte[] server_message_01 = Utils.hexStringToByteArray("93400073a1bbf945930a9e594035b2639046cd56f5cce65998bddd16e92ec0fd7563951c7488da4e2341675e3f692645ad8b064a0b5d3d52017fe1b4fcc1b7cd4843cddba3b8c1");

		// 0x00 CLIENT_CONNECT_TCP [RC_CLIENT_SESSION]
		byte[] client_message_02 = Utils.hexStringToByteArray("804900609cac75edde4cd90feba860ceeb928e9135e48839c45d1e966d00958745ba76242fdec265258545a6daba3bfd7ea3fa2fe944648c0f2398287279369d6b73545101cdad24b78df93ca20cea80");

		// 0x14 SERVER_CRYPTKEY_GAME (UYA) [RC_CLIENT_SESSION]
		byte[] server_message_02 = Utils.hexStringToByteArray("944000f9b9006e511e6a903f3df3716e754e35811b3b25ef5c40755d2ab318b32d80bb5305a8eac885994bf248652a5fe4df07a1b41921d60e7e985d691218146f0051be7f84fb87170068638f72994377ae5716efceacdd410084b5bda0a7b5818952b52b9a02000e356b65fbcd");

		// 0x0b CLIENT_APP_TOSERVER [RC_CLIENT_SESSION]
		byte[] client_message_03 = Utils.hexStringToByteArray("8b1e00a7fd4874218c79d89ca04de52513e26a216373db5f869f69156c70e6f5bcfca0f500");

		// 0x0a CLIENT_APP [RC_SERVER_SESSION]
		byte[] server_message_03 = Utils.hexStringToByteArray("8a32005654fb3251ad61064920ee8f216390e4311a9b66a3ae12fc0c0013a4ed927240d606efa9759689fd67af9ad5633bcbaf460034e5fbf7");

		// 0x0b CLIENT_APP_TOSERVER [RC_CLIENT_SESSION]
		byte[] client_message_04 = Utils.hexStringToByteArray("8b320057aecf603a28a08565ee7ac26dc03148224b51fa3d2078931c94920ab1197589547caf117f8759f9eab6cf3a63486e6d5790e248c753");

		// 0x0a CLIENT_APP [RC_SERVER_SESSION]
		byte[] server_message_04 = Utils.hexStringToByteArray("8a1e00774b2b3e818eebefa821d38222a836a761c6b56c96ab364c0a2d72ccd32d6141b8fb");

		// 0x0b CLIENT_APP_TOSERVER [RC_CLIENT_SESSION]
		byte[] client_message_05 = Utils.hexStringToByteArray("8b520087740b762ca1532d26583aa1ef3f65aa21ce5b10814722d62082e6ffcd8fed5d9d0621a09e4b1979512f7102247b759b8d1e4b6413f71a0db785652e60151e5e9f5f7bfcd9aa8bac55e6c1e465a997901632311b8668");

		// 0x0b CLIENT_APP_TOSERVER [RC_CLIENT_SESSION]
		byte[] client_message_06 = Utils.hexStringToByteArray("8b6800d64a7c6d7654ae04945cd13b0bb44b10da7ea3af748b5028a77f21226d44d981f9ef34804024568a653cfab9e677c3c324ffe77b6a62692157634fdcdfe0ee81788d74d5b95f373c3fa668f237fd0a8e5b8ea9b76a13143853d51acdfb41bc5e81db1b3cecb6110ee220d3b2");

		// 0x0a CLIENT_APP [RC_SERVER_SESSION]
		byte[] server_message_05 = Utils.hexStringToByteArray("8ac600e19716264d42061fbc4abe21b6c4083f74df9c6c11c1fba5b8ffdd3dd390a3078dfaf49a7ebfee41fc17abae3437086911e5b026a6d1120d1b42d3224040199054aefe6cb5cbd55d2e7312e57d0f8f0e989689e69d99e592f3687cfa37dd8800b9f9a1cc1d2b4304b766824a7c0e5d779bf2615e6bc287950b38540c719250ff2db38b8754f034b23f92445cd2addbe6c53109f4f7543a110ad8a51b7694157e4ebf2059fd09d20673f4b2900c24f8390e771b851f9b6095737834fa68ff82729cd717e7d986afb4ccec");

		// 0x01 CLIENT_DISCONNECT
		byte[] client_message_07 = Utils.hexStringToByteArray("010000");

		RawRTMessage rsaKey = attemptDecrypt(new RawRTMessage(client_message_01));

		print(Utils.bytesToHex(rsaKey.toBytes()));

	}

	/**
	 * Decrypt a single message frame.
	 * 
	 * @param message
	 * @return
	 */
	private static RawRTMessage attemptDecrypt(RawRTMessage message) {

		byte id = message.getId();
		byte[] hash = message.getHash();
		short frameLength = message.getLength();
		int totalLength = 3;
		
		
		if (id >= 0x80) {
			hash = message.getHash();
			totalLength += 4;
			id &= 0x7F;
		}

		PS2_RSA rsa = new PS2_RSA(N, E, D);
		print("attemptDecrypt payload: " + Utils.bytesToHex(message.getPayload()));

		SCERTDecryptedData data = rsa.decrypt(message.getPayload(), message.getHash());
		print("attemptDecrypt SCERTDecryptedData: " + Utils.bytesToHex(data.getData()));

		return new RawRTMessage(data.getData());
	}

	/**
	 * Print a message to the console
	 * 
	 * @param s
	 */
	private static void print(String s) {
		System.out.println(s);
	}

}
