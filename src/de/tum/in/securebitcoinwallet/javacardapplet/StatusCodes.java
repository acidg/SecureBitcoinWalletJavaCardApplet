package de.tum.in.securebitcoinwallet.javacardapplet;

/**
 * Error and status codes for the {@link SecureBitcoinWalletJavaCardApplet}.
 * 
 * @author Benedikt Schlagberger
 */
public abstract interface StatusCodes {
	/**
	 * Error code thrown if entered PIN was incorrect.
	 */
	public final static short SW_AUTH_FAILED = (short) 0x6300;

	/**
	 * Error code thrown if the card is locked, because the pin has been entered
	 * wrong to many times.
	 */
	public final static short SW_CARD_LOCKED = (short) 0x6983;

	/**
	 * Used to indicate an error because the given bitcoin address had the wrong
	 * length.
	 */
	public final static short WRONG_ADDRESS_LENGTH = (short) 0x0003;
}
