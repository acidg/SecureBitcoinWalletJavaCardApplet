package de.tum.in.securebitcoinwallet.javacardapplet.test.util;

import java.lang.reflect.Array;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.crypto.digests.RIPEMD160Digest;

public abstract class TestUtils {
	public static <T> T[] concatenate(T[] a, T[] b) {
		int aLen = a.length;
		int bLen = b.length;

		@SuppressWarnings("unchecked")
		T[] c = (T[]) Array.newInstance(a.getClass().getComponentType(), aLen
				+ bLen);
		System.arraycopy(a, 0, c, 0, aLen);
		System.arraycopy(b, 0, c, aLen, bLen);

		return c;
	}

	public static byte[] concatenate(byte[] a, byte[] b) {
		int aLen = a.length;
		int bLen = b.length;

		byte[] c = new byte[aLen + bLen];
		System.arraycopy(a, 0, c, 0, aLen);
		System.arraycopy(b, 0, c, aLen, bLen);

		return c;
	}

	/**
	 * Converts a String in HEX notation to the euivalent byte array.
	 * 
	 * @param hexString String in HEX notation
	 * @return The byte array
	 */
	public static byte[] hexStringToByteArray(String hexString) {
		int len = hexString.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4) + Character
					.digit(hexString.charAt(i + 1), 16));
		}
		return data;
	}

	/**
	 * Creates a String representing the given byte array in HEX notation.
	 * 
	 * @param data The byte array to convert
	 * @return A String representing the given bytes in HEX notation
	 */
	public static String getHexString(byte[] data) {
		StringBuilder builder = new StringBuilder();
		for (byte b : data) {
			builder.append(String.format("%02X", b));
		}
		return builder.toString();
	}

	/**
	 * Calculates the bitcoinaddress for the given byte array containing the
	 * public key and returns it
	 * as a String.
	 *
	 * @param publicKey A byte array containing the public key to calculate the
	 *            address for
	 * @return The Bitcoin address as a Base58 encoded string
	 */
	public static String calculateBitcoinAddress(byte[] publicKey) {
		RIPEMD160Digest ripemd160 = new RIPEMD160Digest();
		MessageDigest sha256;
		try {
			sha256 = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}

		byte[] sha256Hash = sha256.digest(publicKey);

		byte[] ripemdHash = new byte[ripemd160.getDigestSize() + 1];
		ripemd160.update(sha256Hash, 0, sha256Hash.length);
		ripemd160.doFinal(ripemdHash, 1);

		// Set version byte
		ripemdHash[0] = 0;

		sha256Hash = sha256.digest(ripemdHash);
		sha256Hash = sha256.digest(sha256Hash);

		byte[] addressBytes = new byte[ripemdHash.length + 4];

		System.arraycopy(ripemdHash, 0, addressBytes, 0, ripemdHash.length);
		System.arraycopy(sha256Hash, 0, addressBytes, (ripemdHash.length),
				4);

		return Base58.encode(addressBytes);
	}
}
