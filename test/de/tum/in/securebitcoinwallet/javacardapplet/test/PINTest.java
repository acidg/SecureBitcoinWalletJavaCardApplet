package de.tum.in.securebitcoinwallet.javacardapplet.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import javacard.framework.ISO7816;
import javacard.framework.Util;

import org.junit.Test;

import de.tum.in.securebitcoinwallet.javacardapplet.AppletInstructions;
import de.tum.in.securebitcoinwallet.javacardapplet.SecureBitcoinWalletJavaCardApplet;
import de.tum.in.securebitcoinwallet.javacardapplet.StatusCodes;

/**
 * UnitTests for PIN functions.
 * 
 * @author Benedikt Schlagberger
 */
public class PINTest extends AppletTestBase {
	private static final byte[] FAULTY_VALIDATE_INSTRUCTION = {
			AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
			AppletInstructions.INS_AUTHENTICATE, 0x00, // P1
			0x00, // P2
			(byte) SecureBitcoinWalletJavaCardApplet.DEFAULT_PIN.length, // Lc
			0x04, 0x03, 0x02, 0x01 // Wrong PIN
	};

	/**
	 * Tests the PIN validation with the correct PIN.
	 */
	@Test
	public void testCorrectPINValidation() {
		byte[] validateCommand = {
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_AUTHENTICATE, 0x00, // P1
				0x00, // P2
				(byte) SecureBitcoinWalletJavaCardApplet.DEFAULT_PIN.length, 
				0x01, 0x02, 0x03, 0x04 // Default PIN
		};

		byte[] response = simulator.transmitCommand(validateCommand);

		assertCommandSuccessful(response);

		assertTrue(checkPINValidated());
	}

	/**
	 * Tests the PIN validation with a faulty PIN.
	 */
	@Test
	public void testFaultyPINValidation() {
		short response = Util.getShort(
				simulator.transmitCommand(FAULTY_VALIDATE_INSTRUCTION),
				(short) 0);

		assertEquals(StatusCodes.SW_AUTH_FAILED, response);

		assertFalse(checkPINValidated());
	}

	/**
	 * Tests the change PIN function.
	 */
	@Test
	public void testPINchange() {
		testCorrectPINValidation();

		byte[] toNewPINChangeCommand = {
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_CHANGE_PIN, 0x00, // P1
				0x00, // P2
				0x06, // Lc (PIN length)
				0x01, 0x01, 0x01, 0x01, 0x01, 0x01 // New PIN
		};

		byte[] toOldPINChangeCommand = {
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_CHANGE_PIN, 0x00, // P1
				0x00, // P2
				0x04, // Lc (PIN length)
				0x01, 0x02, 0x03, 0x04 // default PIN
		};

		byte[] validateNewPINCommand = {
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_AUTHENTICATE, 0x00, // P1
				0x00, // P2
				0x06, // Length of new PIN
				0x01, 0x01, 0x01, 0x01, 0x01, 0x01 // New PIN
		};

		// Change PIN to 111111
		byte[] response = simulator.transmitCommand(toNewPINChangeCommand);
		assertCommandSuccessful(response);

		// Check PIN
		response = simulator.transmitCommand(validateNewPINCommand);
		assertCommandSuccessful(response);
		assertTrue(checkPINValidated());

		// Revert to default PIN 1234
		response = simulator.transmitCommand(toOldPINChangeCommand);
		assertCommandSuccessful(response);

		// Check old PIN
		testCorrectPINValidation();
	}

	/**
	 * Tests the PUK functionality by trying wrong pins until the card is locked
	 * and unlocking it by using the PUK.
	 */
	@Test
	public void testPUK() {
		short response = StatusCodes.SW_AUTH_FAILED;

		// block the card by attempting authorization with a wrong pin several
		// times
		do {
			response = Util.getShort(
					simulator.transmitCommand(FAULTY_VALIDATE_INSTRUCTION),
					(short) 0);
		} while (response == StatusCodes.SW_AUTH_FAILED);

		assertEquals(StatusCodes.SW_CARD_LOCKED, response);
		assertFalse(checkPINValidated());

		byte[] unlockInstruction = new byte[17];
		unlockInstruction[0] = AppletInstructions.SECURE_BITCOIN_WALLET_CLA;
		unlockInstruction[1] = AppletInstructions.INS_UNLOCK;
		unlockInstruction[2] = SecureBitcoinWalletJavaCardApplet.PUK_SIZE; // P1
		unlockInstruction[3] = (byte) SecureBitcoinWalletJavaCardApplet.DEFAULT_PIN.length; // P2
		unlockInstruction[4] = 0x0C;	// Le
		System.arraycopy(puk, 0, unlockInstruction, ISO7816.OFFSET_CDATA,
				puk.length);
		System.arraycopy(SecureBitcoinWalletJavaCardApplet.DEFAULT_PIN, 0,
				unlockInstruction, ISO7816.OFFSET_CDATA + puk.length,
				SecureBitcoinWalletJavaCardApplet.DEFAULT_PIN.length);

		assertCommandSuccessful(simulator.transmitCommand(unlockInstruction));

		testCorrectPINValidation();
	}

	/**
	 * Checks if the PIN has been validated.
	 * 
	 * @return True, if the previous PIN validation was successful.
	 */
	private boolean checkPINValidated() {
		byte[] isValidatedCommand = {
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_PIN_VALIDATED, 0x00, // P1
				0x00 // P2
		};

		byte[] response = simulator.transmitCommand(isValidatedCommand);

		assertCommandSuccessful(response);

		return response[0] == 1 ? true : false;
	}
}
