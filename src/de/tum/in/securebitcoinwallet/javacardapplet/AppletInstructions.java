package de.tum.in.securebitcoinwallet.javacardapplet;

/**
 * Instructions for the {@link SecureBitcoinWalletJavaCardApplet}.
 * 
 * @author Benedikt Schlagberger
 */
public abstract interface AppletInstructions {
	/**
	 * CLA instruction class for Secure Bitcoin Wallet app instructions.
	 */
	public final static byte SECURE_BITCOIN_WALLET_CLA = (byte) 0xA0;

	/**
	 * Setup Instruction.
	 */
	public final static byte INS_SETUP = (byte) 0x02;

	/**
	 * Unlock instructions. Used to unlock the card, if the pin has been entered
	 * wrong too many times.
	 */
	public final static byte INS_UNLOCK = (byte) 0x22;

	/**
	 * User authentication instruction.
	 */
	public static final byte INS_AUTHENTICATE = (byte) 0x04;

	/**
	 * Set pin instruction.
	 */
	public final static byte INS_CHANGE_PIN = (byte) 0x06;

	/**
	 * Pin validated instruction.
	 */
	public static final byte INS_PIN_VALIDATED = (byte) 0x08;

	/**
	 * Put private key instruction.
	 */
	public static final byte INS_PUT_PRIVATE_KEY = (byte) 0xD8;

	/**
	 * Get private key instruction.
	 */
	public static final byte INS_GET_PRIVATE_KEY = (byte) 0xB0;

	/**
	 * Delete private key instruction.
	 */
	public static final byte INS_DELETE_PRIVATE_KEY = (byte) 0xE4;
}
