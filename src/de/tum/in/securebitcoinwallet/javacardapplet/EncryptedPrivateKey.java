package de.tum.in.securebitcoinwallet.javacardapplet;

import javacard.framework.CardRuntimeException;
import javacard.framework.Util;

/**
 * Wrapper for encrypted private keys. 
 * 
 * @author Benedikt Schlagberger
 */
public class EncryptedPrivateKey {

	/**
	 * The store for the encrypted key.
	 */
	byte[] privateKey;

	/**
	 * Whether this key is in use or can be overwritten.
	 */
	boolean inUse;

	public EncryptedPrivateKey(short keySize) {
		privateKey = new byte[keySize];
		inUse = false;
	}

	public void setKey(byte[] src, short srcOff, short srcLength) {
		if (inUse) {
			CardRuntimeException.throwIt(StatusCodes.KEY_IS_IN_USE);
		}

		if (srcLength != (short) privateKey.length) {
			CardRuntimeException.throwIt(StatusCodes.WRONG_PRIVATE_KEY_LENGTH);
		}
		Util.arrayCopy(src, srcOff, privateKey, (short) 0, srcLength);
	}

	/**
	 * Returns the private key in encrypted form.
	 * 
	 * @param dest The destination where the encrypted private key will be
	 *            placed
	 * @param destOff
	 * @return The length of the encrypted private key or 0 if this key is not
	 *         in use.
	 */
	public short getKey(byte[] dest, short destOff) {
		if (!inUse) {
			return 0;
		}

		Util.arrayCopy(privateKey, (short) 0, dest, destOff,
				(short) privateKey.length);
		return (short) privateKey.length;
	}

	/**
	 * Whether this key is in use.
	 */
	public boolean isInUse() {
		return inUse;
	}

	/**
	 * Deletes this key and makes it usable via
	 * {@link #setKey(byte[], short, short)}.
	 */
	public void clear() {
		Util.arrayFillNonAtomic(privateKey, (short) 0,
				(short) privateKey.length, (byte) 0);
		inUse = false;
	}

	/**
	 * Returns the size of this key.
	 */
	public short getSize() {
		return (short) privateKey.length;
	}
}
