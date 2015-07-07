package de.tum.in.securebitcoinwallet.javacardapplet;

import javacard.framework.CardRuntimeException;
import javacard.framework.Util;

/**
 * Represents a Bitcoin address. Stores the values inside a byte array.
 * 
 * @author Benedikt Schlagberger
 *
 */
public class BitcoinAddress {
	public static short MAX_ADDRESS_LENGTH = 255;

	/**
	 * Byte array holding the address.
	 */
	private byte[] addressBytes;

	/**
	 * Size of the address.
	 */
	private short size;

	/**
	 * Constructor. Initializes the byte array of this BitcoinAddress.
	 * 
	 * @param size The maximum size of an address in bytes. May not exceed 255
	 *            bytes.
	 */
	public BitcoinAddress(short size) {
		if (size > MAX_ADDRESS_LENGTH) {
			CardRuntimeException.throwIt(StatusCodes.WRONG_ADDRESS_LENGTH);
		}

		addressBytes = new byte[size];
		this.size = 0;
	}

	/**
	 * Sets the address bytes of this BitcoinAddress.
	 * 
	 * @param src The array, in which the address can be found
	 * @param addrOff The offset of the address inside the source array
	 * @param addrLength The length of the address (may not exceed 255 bytes).
	 */
	public void setAddress(byte[] src, short addrOff, short addrLength) {
		if ((short) (0xFF & addrLength) > (short) addressBytes.length) {
			CardRuntimeException.throwIt(StatusCodes.WRONG_ADDRESS_LENGTH);
		}

		size = addrLength;
		Util.arrayCopy(src, (byte) addrOff, addressBytes, (byte) 0, addrLength);
	}

	/**
	 * Deletes the contents of this address.
	 */
	public void delete() {
		Util.arrayFillNonAtomic(addressBytes, (short) 0,
				(short) addressBytes.length, (byte) 0);
		size = 0;
	}

	/**
	 * Checks whether this bitcoinAddress is in use.
	 */
	private boolean isInUse() {
		return size != 0;
	}

	/**
	 * Checks whether the given address equals this BitcoinAddress.
	 * 
	 * @param src The array, in which the address can be found
	 * @param addrOff The offset of the address inside the source array
	 * @param addrLength The length of the address
	 * 
	 * @return True if the addresses are equal, false otherwise.
	 */
	public boolean equalsAddress(byte[] src, short addrOff, short addrLength) {
		if (!isInUse()) {
			return false;
		}

		if (size != addrLength) {
			return false;
		}

		return Util.arrayCompare(src, addrOff, addressBytes, (short) 0,
				addrLength) == 0;
	}

	/**
	 * Returns the size of this BitcoinAddress in bytes.
	 */
	public short getSize() {
		return size;
	}
}
