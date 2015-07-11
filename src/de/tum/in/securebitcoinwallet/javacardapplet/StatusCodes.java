package de.tum.in.securebitcoinwallet.javacardapplet;

/**
 * Error and status codes for the {@link SecureBitcoinWalletJavaCardApplet}.
 * 
 * @author Benedikt Schlagberger
 */
public interface StatusCodes {
	/**
	 * Error code thrown if entered PIN was incorrect.
	 */
	short SW_AUTH_FAILED = (short) 0x6300;

	/**
	 * Error code thrown if the card is locked, because the pin has been entered
	 * wrong to many times.
	 */
	short SW_CARD_LOCKED = (short) 0x6983;

	/**
	 * Used to indicate the given bitcoin address had the wrong
	 * length.
	 */
	short WRONG_ADDRESS_LENGTH = (short) 0xA003;

	/**
	 * Used to indicate the given private key has the wrong length.
	 */
	short WRONG_PRIVATE_KEY_LENGTH = (short) 0xA004;

	/**
	 * Used to indicate the key is already in use and has to be deleted first.
	 */
	 short KEY_IS_IN_USE = (short) 0xA005;

	/**
	 * Specified key could not be found.
	 */
	 short KEY_NOT_FOUND = (short) 0xA006;
	
	/**
	 * The KeyStore is full.
	 */
	 short KEYSTORE_FULL = (short) 0xA007;
}
