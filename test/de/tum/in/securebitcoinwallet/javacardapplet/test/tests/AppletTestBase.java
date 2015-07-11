package de.tum.in.securebitcoinwallet.javacardapplet.test.tests;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;

import javacard.framework.ISO7816;

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
	protected CardChannel channel;

	/**
	 * Constructor. Initializes the simulator and selects the applet. Also calls
	 * the setup instruction and retrieves the PUK.
	 * 
	 * @throws CardException
	 * @throws IOException
	 */
	public AppletTestBase() throws CardException {
		TerminalFactory factory = TerminalFactory.getDefault();

		CardTerminal terminal = factory.terminals().list().get(0);
		// establish a connection with the card
		Card card = null;
		card = terminal.connect("*");
		channel = card.getBasicChannel();

		selectAID(AID);
		checkPUK();
	}

	/**
	 * Checks if the PUK has been already set.
	 * 
	 * @throws CardException
	 */
	private void checkPUK() throws CardException {
		File pukFile = new File("bin/puk");
		if (pukFile.exists()) {
			try {
				puk = Files.readAllBytes(pukFile.toPath());
			} catch (IOException e) {
				// Ignore and try setup
			}
		} else {
			CommandAPDU setupInstruction = new CommandAPDU(
					AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
					AppletInstructions.INS_SETUP, 0, 0);
			ResponseAPDU response = channel.transmit(setupInstruction);

			assertTrue(commandSuccessful(response));

			puk = Arrays.copyOf(response.getBytes(),
					SecureBitcoinWalletJavaCardApplet.PUK_SIZE);

			try {
				Files.write(pukFile.toPath(), puk, StandardOpenOption.CREATE);
			} catch (IOException e) {
				throw new RuntimeException("PUK file could not be created in "
						+ pukFile.getAbsolutePath() + "PUK: "
						+ getHexString(puk));
			}
		}
	}

	/**
	 * Authenticate at the smartcard with the given PIN.
	 *
	 * @param pin The PIN to authenticate with
	 * @return The response from the SmartCard
	 * @throws CardException
	 */
	protected ResponseAPDU authenticate(byte[] pin) throws CardException {
		CommandAPDU authenticateCommand = new CommandAPDU(
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_AUTHENTICATE, 0x00, 0x00, pin);

		return channel.transmit(authenticateCommand);
	}

	/**
	 * Checks whether the given response contains the ISO7816 response for
	 * success (0x9000).
	 * 
	 * @param response The response returned by the transmitted APDU command.
	 * 
	 * @return True, if the command was executed successfully, false otherwise.
	 */
	protected boolean commandSuccessful(ResponseAPDU response) {
		int statusCode = (short) response.getSW();
		return ISO7816.SW_NO_ERROR == statusCode;
	}

	/**
	 * Creates a String representing the given byte array in HEY notation.
	 */
	protected String getHexString(byte[] data) {
		StringBuilder builder = new StringBuilder();
		for (byte b : data) {
			builder.append(String.format("%02X ", b) + " ");
		}
		return builder.toString();
	}

	/**
	 * Sends the select aid APDU to the card.
	 * 
	 * @param aid The AID to select
	 * @throws CardException
	 */
	private void selectAID(byte[] aid) throws CardException {
		CommandAPDU selectAIDCommand = new CommandAPDU(0x00, 0xA4, 0x04, 0x00,
				aid);

		ResponseAPDU response = channel.transmit(selectAIDCommand);

		assertTrue(commandSuccessful(response));
	}
}