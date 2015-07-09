package de.tum.in.securebitcoinwallet.javacardapplet.test.tests;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;

import javacard.framework.ISO7816;
import javacard.framework.Util;

import org.junit.Test;

import de.tum.in.securebitcoinwallet.javacardapplet.AppletInstructions;
import de.tum.in.securebitcoinwallet.javacardapplet.SecureBitcoinWalletJavaCardApplet;
import de.tum.in.securebitcoinwallet.javacardapplet.StatusCodes;
import de.tum.in.securebitcoinwallet.javacardapplet.test.TestUtils;

/**
 * UnitTests for PIN functions.
 * 
 * @author Benedikt Schlagberger
 */
public class PINTest extends AppletTestBase {
	public PINTest() throws CardException {
		super();
	}

	private static final byte[] WRONG_PIN = { 0x04, 0x03, 0x02, 0x01 };

	private static final CommandAPDU FAULTY_VALIDATE_INSTRUCTION = new CommandAPDU(
			AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
			AppletInstructions.INS_AUTHENTICATE, 0, 0, WRONG_PIN);

	/**
	 * Tests the PIN validation with the correct PIN.
	 * 
	 * @throws CardException
	 */
	@Test
	public void testCorrectPINValidation() throws CardException {
		CommandAPDU validateCommand = new CommandAPDU(
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_AUTHENTICATE, 0, 0,
				SecureBitcoinWalletJavaCardApplet.DEFAULT_PIN);

		byte[] response = channel.transmit(validateCommand).getBytes();

		assertTrue(commandSuccessful(response));

		assertTrue(checkPINValidated());
	}

	/**
	 * Tests the PIN validation with a faulty PIN.
	 * 
	 * @throws CardException
	 * @throws NullPointerException
	 * @throws ArrayIndexOutOfBoundsException
	 */
	@Test
	public void testFaultyPINValidation()
			throws ArrayIndexOutOfBoundsException, NullPointerException,
			CardException {
		short response = Util.getShort(
				channel.transmit(FAULTY_VALIDATE_INSTRUCTION).getBytes(),
				(short) 0);

		assertEquals(StatusCodes.SW_AUTH_FAILED, response);

		assertFalse(checkPINValidated());
	}

	/**
	 * Tests the change PIN function.
	 * 
	 * @throws CardException
	 */
	@Test
	public void testPINchange() throws CardException {
		testCorrectPINValidation();

		byte[] newPin = { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };

		CommandAPDU toNewPINChangeCommand = new CommandAPDU(
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_CHANGE_PIN, 0, 0, newPin);

		CommandAPDU toOldPINChangeCommand = new CommandAPDU(
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_CHANGE_PIN, 0, 0,
				SecureBitcoinWalletJavaCardApplet.DEFAULT_PIN);

		CommandAPDU validateNewPINCommand = new CommandAPDU(
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_AUTHENTICATE, 0, 0, newPin);

		// Change PIN to 111111
		byte[] response = channel.transmit(toNewPINChangeCommand).getBytes();
		assertTrue(commandSuccessful(response));

		// Check PIN
		response = channel.transmit(validateNewPINCommand).getBytes();
		assertTrue(commandSuccessful(response));
		assertTrue(checkPINValidated());

		// Revert to default PIN 1234
		response = channel.transmit(toOldPINChangeCommand).getBytes();
		assertTrue(commandSuccessful(response));

		// Check old PIN
		testCorrectPINValidation();
	}

	/**
	 * Tests the PUK functionality by trying wrong pins until the card is locked
	 * and unlocking it by using the PUK.
	 * 
	 * @throws CardException
	 */
	@Test
	public void testPUK() throws CardException {
		short response = StatusCodes.SW_AUTH_FAILED;

		// block the card by attempting authorization with a wrong pin several
		// times
		do {
			response = Util.getShort(
					channel.transmit(FAULTY_VALIDATE_INSTRUCTION).getBytes(),
					(short) 0);
		} while (response == StatusCodes.SW_AUTH_FAILED);

		assertEquals(StatusCodes.SW_CARD_LOCKED, response);
		assertFalse(checkPINValidated());

		CommandAPDU unlockInstruction = new CommandAPDU(
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_UNLOCK,
				SecureBitcoinWalletJavaCardApplet.PUK_SIZE,
				SecureBitcoinWalletJavaCardApplet.DEFAULT_PIN.length,
				TestUtils.concatenate(puk,
						SecureBitcoinWalletJavaCardApplet.DEFAULT_PIN));

		System.arraycopy(SecureBitcoinWalletJavaCardApplet.DEFAULT_PIN, 0,
				unlockInstruction, ISO7816.OFFSET_CDATA + puk.length,
				SecureBitcoinWalletJavaCardApplet.DEFAULT_PIN.length);

		assertTrue(commandSuccessful(channel.transmit(unlockInstruction)
				.getBytes()));

		testCorrectPINValidation();
	}

	/**
	 * Checks if the PIN has been validated.
	 * 
	 * @return True, if the previous PIN validation was successful.
	 * @throws CardException 
	 */
	private boolean checkPINValidated() throws CardException {
		CommandAPDU isValidatedCommand = new CommandAPDU(
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_PIN_VALIDATED, 0, 0);

		byte[] response = channel.transmit(isValidatedCommand).getBytes();

		assertTrue(commandSuccessful(response));

		return response[0] == 1 ? true : false;
	}
}
