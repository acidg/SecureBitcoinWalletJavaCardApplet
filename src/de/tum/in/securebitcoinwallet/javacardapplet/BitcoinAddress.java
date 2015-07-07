package de.tum.in.securebitcoinwallet.javacardapplet;

import javacard.framework.CardRuntimeException;
import javacard.framework.Util;

/**
 * Represents a Bitcoin address. Stores the values inside a byte array. The
 * first byte of the array defines the length of the address.
 * 
 * @author Benedikt Schlagberger
 *
 */
public class BitcoinAddress {
	private byte[] addressBytes;

	/**
	 * Constructor. Initializes the byte array of this BitcoinAddress.
	 * 
	 * @param size The maximum size of an address in bytes. May not exceed 254
	 *            bytes.
	 */
	public BitcoinAddress(short size) {
		if (size > 254) {
			CardRuntimeException.throwIt(StatusCodes.WRONG_ADDRESS_LENGTH);
		}

		addressBytes = new byte[(short) (size + 1)];
	}

	/**
	 * Sets the address bytes of this BitcoinAddress.
	 * 
	 * @param src The array, in which the address can be found
	 * @param addrOff The offset of the address inside the source array
	 * @param addrLength The length of the address (may not exceed 254 bytes).
	 */
	public void setAddress(byte[] src, short addrOff, short addrLength) {
		if (addrLength > 254
				|| (short) (0xFF & addrLength) > (short) (addressBytes.length - 1)) {
			CardRuntimeException.throwIt(StatusCodes.WRONG_ADDRESS_LENGTH);
		}

		addressBytes[0] = (byte) (addrLength & 0xFF);
		Util.arrayCopy(src, (byte) addrOff, addressBytes, (byte) 1, addrLength);
	}

	/**
	 * Deletes the contents of this address.
	 */
	public void delete() {
		Util.arrayFillNonAtomic(addressBytes, (short) 0,
				(short) addressBytes.length, (byte) 0);
	}

	/**
	 * Checks whether this bitcoinAddress is in use.
	 */
	private boolean isInUse() {
		return addressBytes[0] != 0;
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

		if ((short) (addressBytes[0] & 0xFF) != addrLength) {
			return false;
		}

		return Util.arrayCompare(src, addrOff, addressBytes, (short) 1,
				addrLength) == 0;
	}

	/**
	 * Returns the size of this BitcoinAddress in bytes.
	 */
	public short getSize() {
		return (short) (addressBytes[0] & 0xFF);
	}
}
