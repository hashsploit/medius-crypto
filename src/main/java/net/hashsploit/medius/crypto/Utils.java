package net.hashsploit.medius.crypto;

public class Utils {
	
	// Prevent instantiation
	private Utils() {}
	
	/**
	 * Check of a sequence of bytes equals another sequence of bytes exactly.
	 * @param arr1
	 * @param arr2
	 * @return
	 */
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
	
	/**
	 * Encode a single byte to a string.
	 * @param data
	 * @return
	 */
	public static final String byteToHex(byte data) {
		return "" + (data < 10 ? "0" + data : data);
	}
	
	/**
	 * Encode a byte array to a string of hex.
	 * @param data
	 * @return
	 */
	public static final String bytesToHex(byte[] data) {
		final StringBuilder sb = new StringBuilder();
		for (int i = 0; i < data.length; ++i) {
			sb.append(String.format("%02X", data[i]));
		}
		return sb.toString();
	}
	
	public static byte[] flipByteArray(byte[] array) {
	      byte[] result = new byte[array.length];
	      for (int i = 0; i < array.length; i++) {
	    	  result[array.length-1-i] = array[i];
	      }
	      return result;
	}
	
	/**
	 * Convert a hex string to a byte array. Must be full bytes! AE13 ... etc.
	 * 
	 * @param hexString
	 * @return
	 */
	public static byte[] hexStringToByteArray(final String hexString) {
		final int len = hexString.length();
		final byte[] data = new byte[len / 2];

		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4) + Character.digit(hexString.charAt(i + 1), 16));
		}

		return data;
	}

}
