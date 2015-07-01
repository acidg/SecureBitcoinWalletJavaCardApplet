package de.tum.in.securebitcoinwallet.javacardapplet;

import javacard.security.Key;

public class KeyStore {

	/**
	 * The store for the private keys. If a key is null, the slot is free and
	 * can be used for a new key. This should be kept in sync with
	 * {@link #addressToKeyMap}.
	 */
	private Key[] keys;

	/**
	 * Map to find the key for a specified address. The first dimension is for
	 * the number, under which the key for the address can be found in the
	 * {@link keys} array.
	 * inside the key store. The size of the address is stored in the first byte
	 * of the addresse's array.
	 */
	private byte[][] addressToKeyMap;

	/**
	 * Constructor. Has to be called inside the constructor of the applet to
	 * reserve needed memory.
	 * 
	 * @param storeSize The size of the keystore in keys. Maximum is 254 (0xFE).
	 *            If a storeSize bigger than 254 is provided, the size will be
	 *            set to 254.
	 * @param addressSize The maximum size of an address in bytes. Maximum is
	 *            254. If the maximum is exceeded, the maximum of 254 is used
	 *            instead.
	 */
	public KeyStore(byte storeSize, byte addressSize) {
		if (storeSize == 0xFF) {
			storeSize = (byte) 0xFE;
		}

		if (addressSize == 0xFF) {
			addressSize = (byte) 0xFE;
		}
		keys = new Key[storeSize];
		// first byte in the second dimension is for the size of the address in
		// bytes
		addressToKeyMap = new byte[storeSize][addressSize + 1];
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
