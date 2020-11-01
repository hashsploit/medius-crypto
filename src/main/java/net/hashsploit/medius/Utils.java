package net.hashsploit.medius;

public class Utils {
	
	// Prevent instantiation
	private Utils() {}
	
	public static boolean sequenceEquals(byte[] arr1, byte[] arr2) {
		if (arr1.length != arr2.length) {
			return false;
		}
		for (int i = 0; i < arr1.length; i++) {
			if (arr1[i] != arr2[i]) {
				return false;
			}
		}
		return true;
	}
	
	public static final String byteToHex(byte data) {
		return "0x" + (data < 10 ? "0" + data : data);
	}
	
	public static final String bytesToHex(byte[] buffer) {
		final StringBuilder sb = new StringBuilder();
		for (int i = 0; i < buffer.length; ++i) {
			sb.append(String.format("%02X", buffer[i]));
		}
		return sb.toString();
	}
	
}
