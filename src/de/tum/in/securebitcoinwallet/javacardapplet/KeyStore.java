package de.tum.in.securebitcoinwallet.javacardapplet;

import javacard.framework.Util;
import javacard.security.Key;
import javacard.security.KeyBuilder;

import com.licel.jcardsim.crypto.ECPrivateKeyImpl;

/**
 * Storage for private keys. Uses two arrays to store the private key and a
 * mapping array with addresses. The mapping array is used to easily find the
 * private key for a given address.
 * 
 * @author Benedikt Schlagberger
 */
public class KeyStore {

	/**
	 * Size of a private key in bits. Is 256 for Bitcoin.
	 */
	public static short PRIVATE_KEY_SIZE = 256;

	/**
	 * The store for the private keys. If a key is null, the slot is free and
	 * can be used for a new key. This should be kept in sync with
	 * {@link #addressToKeyIndexMap}.
	 */
	private Key[] keys;

	/**
	 * Map to find the key for a specified address. The first dimension is for
	 * the number, under which the key for the address can be found in the
	 * {@link keys} array. inside the key store. The size of the address is
	 * stored in the first byte of the addresse's array.
	 */
	private byte[][] addressToKeyIndexMap;

	/**
	 * Index of the key inside the {@link keys} array.
	 */
	private short addressIndex;

	/**
	 * Constructor. Has to be called inside the constructor of the applet to
	 * reserve needed memory.
	 * 
	 * @param storeSize
	 *            The size of the keystore in keys. Maximum is 254 (0xFE). If a
	 *            storeSize bigger than 254 is provided, the size will be set to
	 *            254.
	 * @param addressSize
	 *            The maximum size of an address in bytes. Maximum is 254. If
	 *            the maximum is exceeded, the maximum of 254 is used instead.
	 */
	public KeyStore(short storeSize, short addressSize) {
		addressIndex = 0;

		if (storeSize == 0xFF) {
			storeSize = (byte) 0xFE;
		}

		if (addressSize == 0xFF) {
			addressSize = (byte) 0xFE;
		}

		keys = new Key[storeSize];

		// first byte in the second dimension is for the size of the address in
		// bytes
		addressToKeyIndexMap = new byte[storeSize][addressSize + 1];
	}

	/**
	 * Returns the private key for the given address key, or null, if the key
	 * could not be found.
	 * 
	 * @param src
	 *            The byte array in which the address can be found
	 * @param addrOff
	 *            Offset of the address inside the given byte array
	 * @param addrLength
	 *            Length of the address
	 */
	public Key getPrivateKey(byte[] src, short addrOff, short addrLength) {
		calculateIndexForAddress(src, addrOff, addrLength);
		if (addressIndex == 0xFF) {
			return null;
		}

		return keys[addressIndex];
	}

	/**
	 * Returns the index of the key for the given address.
	 * 
	 * @param src
	 *            The byte array in which the address can be found
	 * @param addrOff
	 *            Offset of the address inside the given byte array
	 * @param addrLength
	 *            Length of the address
	 */
	private void calculateIndexForAddress(byte[] src, short addrOff,
			short addrLength) {
		for (addressIndex = 0; addressIndex < addressToKeyIndexMap.length; addressIndex++) {
			if (addressToKeyIndexMap[addressIndex][0] == addrLength) {
				if (Util.arrayCompare(addressToKeyIndexMap[addressIndex],
						(short) 1, src, addrOff, addrLength) == 0) {
					return;
				}
			}
		}
		addressIndex = (byte) 0xFF;
	}

	/**
	 * Stores the given private key in the key store.
	 * 
	 * @param src
	 *            The byte array, in which the address and private key can be
	 *            found.
	 * @param addrOff
	 *            Offset for the address inside the byte array
	 * @param addrLength
	 *            Length of the address
	 * @param keyOff
	 *            Offset of the private key inside the byte array
	 * @param keyLength
	 *            Length of the private key
	 * 
	 * @return True, if the key could be saved, false if the store is full, the
	 *         address is too long or the address is already in the key store.
	 */
	public boolean putPrivateKey(byte[] src, short addrOff, byte addrLength,
			short keyOff, byte keyLength) {
		addressIndex = findFirstFreePosition();
		if (addressIndex == 0xFF
				|| addrLength > addressToKeyIndexMap[0].length - 1) {
			return false;
		}

		// Store private key to keys array of this key store
		keys[addressIndex] = new ECPrivateKeyImpl(
				KeyBuilder.TYPE_EC_FP_PRIVATE, PRIVATE_KEY_SIZE);

		// Add length of address to mapping array
		addressToKeyIndexMap[addressIndex][0] = addrLength;
		// Add mapping
		Util.arrayCopy(src, (byte) addrOff, addressToKeyIndexMap[addressIndex],
				(byte) 1, addrLength);
		return true;
	}

	/**
	 * Deletes the private key for the given address. If the key could not be
	 * found, nothing is done.
	 * 
	 * @param src
	 *            The byte array, in which the address and private key can be
	 *            found.
	 * @param addrOff
	 *            Offset for the address inside the byte array
	 * @param addrLength Length of the address
	 */
	public void removePrivateKey(byte[] src, short addrOff, short addrLength) {
		calculateIndexForAddress(src, addrOff, addrLength);
		if (addressIndex != 0xFF) {
			Util.arrayFillNonAtomic(addressToKeyIndexMap[addressIndex],
					(short) 0,
					(short) addressToKeyIndexMap[addressIndex].length, (byte) 0);
			keys[addressIndex] = null;
		}
	}

	/**
	 * Returns the index of the first free slot inside the key array. If no free
	 * slot could be found, 255 (0xFF) is returned.
	 */
	private byte findFirstFreePosition() {
		for (byte i = 0; i < keys.length; i++) {
			if (keys[i] == null) {
				return i;
			}
		}
		return (byte) 0xFF;
	}
}
