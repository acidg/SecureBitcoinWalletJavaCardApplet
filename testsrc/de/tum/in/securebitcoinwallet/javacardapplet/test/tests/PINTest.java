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
import de.tum.in.securebitcoinwallet.javacardapplet.test.util.TestUtils;

/**
 * UnitTests for PIN functions.
 * 
 * @author Benedikt Schlagberger
 */
public class PINTest extends AppletTestBase {
	private static final byte[] WRONG_PIN = { 4, 3, 2, 1 };

	public PINTest() throws CardException {
		super();
	}

	/**
	 * Tests the PIN validation with the correct PIN.
	 * 
	 * @return True if the pin was correctly validated.
	 */
	@Test
	public void testCorrectPINValidation() throws CardException {
		assertTrue(authenticate(SecureBitcoinWalletJavaCardApplet.DEFAULT_PIN));
	}

	/**
	 * Tests the PIN validation with a faulty PIN.
	 */
	@Test
	public void testFaultyPINValidation() throws CardException {
		assertFalse(authenticate(WRONG_PIN));
	}

	/**
	 * Tests the change PIN function.
	 */
	@Test
	public void testPINchange() throws CardException {
		byte[] newPin = { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };

		assertTrue(authenticate(SecureBitcoinWalletJavaCardApplet.DEFAULT_PIN));
		
		changePin(newPin);

		assertFalse(authenticate(SecureBitcoinWalletJavaCardApplet.DEFAULT_PIN));

		assertTrue(authenticate(newPin));

		changePin(SecureBitcoinWalletJavaCardApplet.DEFAULT_PIN);

		assertFalse(authenticate(newPin));

		assertTrue(authenticate(SecureBitcoinWalletJavaCardApplet.DEFAULT_PIN));
	}

	/**
	 * Tests the PUK functionality by trying wrong pins until the card is locked
	 * and unlocking it by using the PUK.
	 */
	@Test
	public void testPUK() throws CardException {
		ResponseAPDU response;

		CommandAPDU faultyAuthenticateInstruction = new CommandAPDU(
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_AUTHENTICATE, 0, 0,
				WRONG_PIN);
		
		CommandAPDU unlockInstruction = new CommandAPDU(
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_UNLOCK,
				puk.length,
				SecureBitcoinWalletJavaCardApplet.DEFAULT_PIN.length,
				TestUtils.concatenate(puk,
						SecureBitcoinWalletJavaCardApplet.DEFAULT_PIN));

		// block the card by authorization with a wrong pin several times
		do {
			response = smartCard.transmit(faultyAuthenticateInstruction);
		} while ((short) response.getSW() == StatusCodes.AUTH_FAILED);

		assertEquals(StatusCodes.CARD_LOCKED, (short) response.getSW());
		
		assertFalse(checkPINValidated());

		response = smartCard.transmit(unlockInstruction);

		assertTrue(commandSuccessful(response));

		assertTrue(authenticate(SecureBitcoinWalletJavaCardApplet.DEFAULT_PIN));
	}

	/**
	 * Changes the PIN.
	 * 
	 * @param newPin The new PIN
	 */
	private void changePin(byte[] newPin) throws CardException {
		CommandAPDU changePINCommand = new CommandAPDU(
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_CHANGE_PIN, 0, 0, newPin);

		ResponseAPDU response = smartCard.transmit(changePINCommand);

		assertTrue(commandSuccessful(response));
	}
}
