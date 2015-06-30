package de.tum.in.securebitcoinwallet.javacardapplet.test;

import java.io.IOException;

import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.Util;
import static org.junit.Assert.*;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;
import org.junit.Assert;

import de.tum.in.securebitcoinwallet.javacardapplet.SecureBitcoinWalletJavaCardApplet;


/**
 * UnitTests for PIN functions.
 * 
 * @author Benedikt Schlagberger
 */
public class PINTest extends AppletTestBase {
	/**
	 * Tests the PIN validation with the correct PIN.
	 */
	@Test
	public void testCorrectPINValidation() {
		byte[] validateCommand = {
				SecureBitcoinWalletJavaCardApplet.SECURE_BITCOIN_WALLET_CLA,
				SecureBitcoinWalletJavaCardApplet.INS_AUTHENTICATE,
				0x00,	// P1
				0x00,	// P2
				(byte) SecureBitcoinWalletJavaCardApplet.DEFAULT_PIN.length,	// PIN length
				0x01, 0x02, 0x03, 0x04	// Default PIN
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
		byte[] validateCommand = {
				SecureBitcoinWalletJavaCardApplet.SECURE_BITCOIN_WALLET_CLA,
				SecureBitcoinWalletJavaCardApplet.INS_AUTHENTICATE,
				0x00,	// P1
				0x00,	// P2
				(byte) SecureBitcoinWalletJavaCardApplet.DEFAULT_PIN.length,	// Lc
				0x04, 0x03, 0x02, 0x01	// Wrong PIN
		};
		
		short response = Util.getShort(simulator.transmitCommand(validateCommand), (short) 0);
		
		assertEquals(SecureBitcoinWalletJavaCardApplet.SW_AUTH_FAILED, response);
		
		assertFalse(checkPINValidated());
	}
	
	
	/**
	 * Tests the change PIN function.
	 */
	@Test
	public void testPINchange() {
		testCorrectPINValidation();
		
		byte[] toNewPINChangeCommand = {
				SecureBitcoinWalletJavaCardApplet.SECURE_BITCOIN_WALLET_CLA,
				SecureBitcoinWalletJavaCardApplet.INS_CHANGE_PIN,
				0x00,	// P1
				0x00,	// P2
				0x07,	// Lc
				0x06,	// Length of new PIN
				0x01, 0x01, 0x01, 0x01, 0x01, 0x01	// New PIN
		};
		
		byte[] toOldPINChangeCommand = {
				SecureBitcoinWalletJavaCardApplet.SECURE_BITCOIN_WALLET_CLA,
				SecureBitcoinWalletJavaCardApplet.INS_CHANGE_PIN,
				0x00,	// P1
				0x00,	// P2
				0x05,	// Lc
				0x04,	// PIN length
				0x01, 0x02, 0x03, 0x04 // default PIN
		};
		
		byte[] validateNewPINCommand = {
				SecureBitcoinWalletJavaCardApplet.SECURE_BITCOIN_WALLET_CLA,
				SecureBitcoinWalletJavaCardApplet.INS_AUTHENTICATE,
				0x00,	// P1
				0x00,	// P2
				0x06,	// Length of new PIN
				0x01, 0x01, 0x01, 0x01, 0x01, 0x01	// New PIN
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
	 * Checks if the PIN has been validated.
	 * @return True, if the previous PIN validation was successful.
	 */
	private boolean checkPINValidated() {
		byte[] isValidatedCommand = {
				SecureBitcoinWalletJavaCardApplet.SECURE_BITCOIN_WALLET_CLA,
				SecureBitcoinWalletJavaCardApplet.INS_PIN_VALIDATED,
				0x00,	// P1
				0x00	// P2
		};
		
		byte[] response = simulator.transmitCommand(isValidatedCommand);
		
		assertCommandSuccessful(response);
		
		return response[0] == 1 ? true : false;
	}
}
