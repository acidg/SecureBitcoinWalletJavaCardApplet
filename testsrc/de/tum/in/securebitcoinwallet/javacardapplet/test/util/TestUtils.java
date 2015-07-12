package de.tum.in.securebitcoinwallet.javacardapplet.test.util;

import java.lang.reflect.Array;

public abstract class TestUtils {
	public static <T> T[] concatenate (T[] a, T[] b) {
	    int aLen = a.length;
	    int bLen = b.length;

	    @SuppressWarnings("unchecked")
	    T[] c = (T[]) Array.newInstance(a.getClass().getComponentType(), aLen+bLen);
	    System.arraycopy(a, 0, c, 0, aLen);
	    System.arraycopy(b, 0, c, aLen, bLen);

	    return c;
	}

	public static byte[] concatenate(byte[] a, byte[] b) {
		int aLen = a.length;
	    int bLen = b.length;

	    byte[] c = new byte[aLen +bLen];
	    System.arraycopy(a, 0, c, 0, aLen);
	    System.arraycopy(b, 0, c, aLen, bLen);

	    return c;
	}

	/**
	 * Creates a String representing the given byte array in HEX notation.
	 */
	public static String getHexString(byte[] data) {
		StringBuilder builder = new StringBuilder();
		for (byte b : data) {
			builder.append(String.format("%02X", b));
		}
		return builder.toString();
	}
}
