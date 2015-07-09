package de.tum.in.securebitcoinwallet.javacardapplet.test.tests;

import java.util.Arrays;

import javacard.framework.ISO7816;
import javacard.framework.Util;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import de.tum.in.securebitcoinwallet.javacardapplet.AppletInstructions;
import de.tum.in.securebitcoinwallet.javacardapplet.SecureBitcoinWalletJavaCardApplet;

/**
 * Base class for Java Card applet tests.
 * 
 * @author Benedikt Schlagberger
 */
public abstract class AppletTestBase {

	/**
	 * The AID of the Secure Bitcoin Wallet Applet.
	 */
	protected static final String AID = "01020304050607080900";

	protected final byte[] puk;

	protected CardChannel channel;

	/**
	 * Constructor. Initializes the simulator and selects the applet. Also calls
	 * the setup instruction and retrieves the PUK.
	 * 
	 * @throws CardException
	 */
	public AppletTestBase() throws CardException {
		CommandAPDU setupInstruction = new CommandAPDU(
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_SETUP, 0, 0);

		TerminalFactory factory = TerminalFactory.getDefault();
		CardTerminal terminal = factory.terminals().list().get(0);
		// establish a connection with the card
		Card card = null;
		card = terminal.connect("*");
		System.out.println("card: " + card);
		channel = card.getBasicChannel();
		ResponseAPDU r = channel.transmit(setupInstruction);
		System.out.println("response: " + getHexString(r.getBytes()));

		puk = Arrays.copyOf(r.getBytes(),
				SecureBitcoinWalletJavaCardApplet.PUK_SIZE);
	}

	/**
	 * Authenticate at the smartcard with the given PIN.
	 *
	 * @param pin The PIN to authenticate with
	 * @return The response from the SmartCard
	 * @throws CardException
	 */
	protected byte[] authenticate(byte[] pin) throws CardException {
		byte[] apduHeader = { AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_AUTHENTICATE, 0x00, 0x00,
				(byte) pin.length };

		byte[] apdu = new byte[apduHeader.length + pin.length];

		for (int i = 0; i < apduHeader.length; i++) {
			apdu[i] = apduHeader[i];
		}
		for (int i = 0; i < pin.length; i++) {
			apdu[i + apduHeader.length] = pin[i];
		}

		return channel.transmit(new CommandAPDU(apdu)).getBytes();
	}

	/**
	 * Checks whether the given response contains the ISO7816 response for
	 * success (0x9000).
	 * 
	 * @param response The response returned by the transmitted APDU command.
	 * 
	 * @return True, if the command was executed successfully, false otherwise.
	 */
	protected boolean commandSuccessful(byte[] response) {
		short statusCode = Util.getShort(response,
				(short) (response.length - 2));
		return ISO7816.SW_NO_ERROR == statusCode;
	}

	protected String getHexString(byte[] data) {
		StringBuilder builder = new StringBuilder();
		for (byte b : data) {
			builder.append(String.format("%02X ", b) + " ");
		}
		return builder.toString();
	}
}