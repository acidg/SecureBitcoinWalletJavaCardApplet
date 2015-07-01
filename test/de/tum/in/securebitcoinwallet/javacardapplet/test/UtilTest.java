package de.tum.in.securebitcoinwallet.javacardapplet.test;

import org.junit.Test;

import de.tum.in.securebitcoinwallet.javacardapplet.AppletInstructions;

public class UtilTest extends AppletTestBase {
	@Test
	public void testRemainingMemory() {
		byte[] apdu = {
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_GET_REMAINING_MEMORY,
				0,0
		};
		
		byte[] response = simulator.transmitCommand(apdu);
		
		assertCommandSuccessful(response);
	}
}
