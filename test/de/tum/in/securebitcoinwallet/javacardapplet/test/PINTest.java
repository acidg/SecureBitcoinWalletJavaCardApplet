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
				(byte) SecureBitcoinWalletJavaCardApplet.DEFAULT_PIN.length,	// Lc
				0x01,
				0x02,
				0x03,
				0x04
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
				0x04,
				0x03,
				0x02,
				0x01
		};
		
		short response = Util.getShort(simulator.transmitCommand(validateCommand), (short) 0);
		
		assertEquals(SecureBitcoinWalletJavaCardApplet.SW_AUTH_FAILED, response);
		
		assertFalse(checkPINValidated());
	}
	
	
	/**
	 * Tests the change pin function.
	 */
	@Test
	public void testPINchange() {
		testCorrectPINValidation();
		
		byte[] toNewPINChangeCommand = {
				SecureBitcoinWalletJavaCardApplet.SECURE_BITCOIN_WALLET_CLA,
				SecureBitcoinWalletJavaCardApplet.INS_CHANGE_PIN,
				0x00,
				0x00,
				0x07,	// Lc
				0x06,	// Length of new PIN
				0x01,	// new PIN
				0x01,
				0x01,
				0x01,
				0x01,
				0x01
		};
		
		byte[] toOldPINChangeCommand = {
				SecureBitcoinWalletJavaCardApplet.SECURE_BITCOIN_WALLET_CLA,
				SecureBitcoinWalletJavaCardApplet.INS_CHANGE_PIN,
				0x00,
				0x00,
				0x05,
				0x04,
				0x01, 
				0x02,
				0x03,
				0x04
		};
		
		byte[] validateNewPINCommand = {
				SecureBitcoinWalletJavaCardApplet.SECURE_BITCOIN_WALLET_CLA,
				SecureBitcoinWalletJavaCardApplet.INS_AUTHENTICATE,
				0x00,	// P1
				0x00,	// P2
				0x06,	// Lc
				0x01,
				0x01,
				0x01,
				0x01,
				0x01,
				0x01
		};
		
		short response = Util.getShort(simulator.transmitCommand(toNewPINChangeCommand), (short) 0);
		String hans = "0x" + String.format("%02X ", response);
		assertEquals(ISO7816.SW_NO_ERROR, response);
		response = Util.getShort(simulator.transmitCommand(validateNewPINCommand), (short) 0);
		hans = "0x" + String.format("%02X ", response);
		assertEquals(ISO7816.SW_NO_ERROR, response);
		
		assertTrue(checkPINValidated());
		
		response = Util.getShort(simulator.transmitCommand(toOldPINChangeCommand), (short) 0);
		hans = "0x" + String.format("%02X ", response);
		assertEquals(ISO7816.SW_NO_ERROR, response);
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
				0x00,
				0x00
		};
		
		byte[] response = simulator.transmitCommand(isValidatedCommand);
		
		assertCommandSuccessful(response);
		
		return response[0] == 1 ? true : false;
	}
}
