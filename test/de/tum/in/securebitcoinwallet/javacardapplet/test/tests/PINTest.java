package de.tum.in.securebitcoinwallet.javacardapplet.test.tests;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

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

		ResponseAPDU response = channel.transmit(validateCommand);

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
		ResponseAPDU response = channel.transmit(FAULTY_VALIDATE_INSTRUCTION);
		
		assertEquals(StatusCodes.SW_AUTH_FAILED, (short) response.getSW());

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
		ResponseAPDU response = channel.transmit(toNewPINChangeCommand);
		assertTrue(commandSuccessful(response));

		// Check PIN
		response = channel.transmit(validateNewPINCommand);
		assertTrue(commandSuccessful(response));
		assertTrue(checkPINValidated());

		// Revert to default PIN 1234
		response = channel.transmit(toOldPINChangeCommand);
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
		ResponseAPDU response;

		// block the card by attempting authorization with a wrong pin several
		// times
		do {
			response = channel.transmit(FAULTY_VALIDATE_INSTRUCTION);
		} while ((short) response.getSW() == StatusCodes.SW_AUTH_FAILED);

		assertEquals(StatusCodes.SW_CARD_LOCKED, (short) response.getSW());
		assertFalse(checkPINValidated());

		CommandAPDU unlockInstruction = new CommandAPDU(
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_UNLOCK,
				SecureBitcoinWalletJavaCardApplet.PUK_SIZE,
				SecureBitcoinWalletJavaCardApplet.DEFAULT_PIN.length,
				TestUtils.concatenate(puk,
						SecureBitcoinWalletJavaCardApplet.DEFAULT_PIN));

		assertTrue(commandSuccessful(channel.transmit(unlockInstruction)));

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

		ResponseAPDU response = channel.transmit(isValidatedCommand);

		assertTrue(commandSuccessful(response));

		return response.getBytes()[0] == 1 ? true : false;
	}
}
