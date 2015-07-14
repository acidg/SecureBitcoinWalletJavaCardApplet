package de.tum.in.securebitcoinwallet.javacardapplet.test.tests;

import static org.junit.Assert.assertEquals;

import javax.smartcardio.CardException;

import org.junit.Test;

import de.tum.in.securebitcoinwallet.javacardapplet.SecureBitcoinWalletJavaCardApplet;

public class UtilTest extends AppletTestBase {
	public UtilTest() throws CardException {
		super();
	}

	@Test
	public void testRemainingMemory() throws CardException {
		int remainingSlots = getRemainingSlots();
		
		assertEquals(remainingSlots, SecureBitcoinWalletJavaCardApplet.STORE_SIZE);
	}
}
