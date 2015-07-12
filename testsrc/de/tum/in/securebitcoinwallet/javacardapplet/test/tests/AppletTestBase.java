package de.tum.in.securebitcoinwallet.javacardapplet.test.tests;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;

import java.io.IOException;

import javacard.framework.ISO7816;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import de.tum.in.securebitcoinwallet.javacardapplet.AppletInstructions;
import de.tum.in.securebitcoinwallet.javacardapplet.StatusCodes;
import de.tum.in.securebitcoinwallet.javacardapplet.test.JavaCard;
import de.tum.in.securebitcoinwallet.javacardapplet.test.JavaCardHardware;
import de.tum.in.securebitcoinwallet.javacardapplet.test.JavaCardSimulator;

/**
 * Base class for Java Card applet tests.
 * 
 * @author Benedikt Schlagberger
 */
public abstract class AppletTestBase {

	private static boolean USE_SIMULATOR = false;

	/**
	 * The AID of the Issuer Security Domain.
	 */
	protected static final byte[] ISD_AID = { (byte) 0xA0, 0x00, 0x00, 0x01,
			0x51, 0x00, 0x00, 0x00 };
	/**
	 * The AID of the Secure Bitcoin Wallet Applet.
	 */
	protected static final byte[] AID = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
			0x07, 0x08, 0x09, 0x00 };

	/**
	 * PUK.
	 */
	protected byte[] puk;

	/**
	 * CardChannel used to transmit commands.
	 */
	protected JavaCard smartCard;

	/**
	 * Constructor. Initializes the simulator and selects the applet. Also calls
	 * the setup instruction and retrieves the PUK.
	 * 
	 * @throws CardException
	 * @throws IOException
	 */
	public AppletTestBase() throws CardException {
		if (USE_SIMULATOR) {
			smartCard = new JavaCardSimulator(AID);
		} else {
			smartCard = new JavaCardHardware(AID);
		}

		puk = smartCard.setup();
	}

	/**
	 * Checks whether the given response contains the ISO7816 response for
	 * success (0x9000).
	 * 
	 * @param response The response returned by the transmitted APDU command.
	 * 
	 * @return True, if the command was executed successfully, false otherwise.
	 */
	public static boolean commandSuccessful(ResponseAPDU response) {
		int statusCode = (short) response.getSW();
		return ISO7816.SW_NO_ERROR == statusCode;
	}

	/**
	 * Creates a String representing the given byte array in HEY notation.
	 */
	public static String getHexString(byte[] data) {
		StringBuilder builder = new StringBuilder();
		for (byte b : data) {
			builder.append(String.format("%02X ", b) + " ");
		}
		return builder.toString();
	}

	/**
	 * Authenticate at the smartcard with the given PIN.
	 *
	 * @param pin The PIN to authenticate with
	 * @return True, if the authentication was successful, false otherwise
	 * @throws CardException
	 */
	protected boolean authenticate(byte[] pin) throws CardException {
		CommandAPDU authenticateCommand = new CommandAPDU(
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_AUTHENTICATE, 0x00, 0x00, pin);
	
		ResponseAPDU response = smartCard.transmit(authenticateCommand);
		
		boolean result = false;
		
		switch ((short) response.getSW()) {
		case StatusCodes.SW_AUTH_FAILED:
		case StatusCodes.SW_CARD_LOCKED:
			break;
		case ISO7816.SW_NO_ERROR:
			result = true;
			break;
		default:
			throw new RuntimeException("Unknown StatusCode: " + getHexString(response.getBytes()));
		}
		
		assertEquals(checkPINValidated(), result);
		return result;
	}

	/**
	 * Checks if the PIN has been validated.
	 * 
	 * @return True, if the previous PIN validation was successful.
	 * @throws CardException
	 */
	protected boolean checkPINValidated() throws CardException {
		CommandAPDU isValidatedCommand = new CommandAPDU(
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_PIN_VALIDATED, 0, 0);

		ResponseAPDU response = smartCard.transmit(isValidatedCommand);

		assertTrue(commandSuccessful(response));

		return response.getBytes()[0] == 1 ? true : false;
	}
}