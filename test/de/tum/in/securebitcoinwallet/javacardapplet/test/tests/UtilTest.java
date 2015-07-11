package de.tum.in.securebitcoinwallet.javacardapplet.test.tests;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.junit.Test;

import de.tum.in.securebitcoinwallet.javacardapplet.AppletInstructions;

public class UtilTest extends AppletTestBase {
	public UtilTest() throws CardException {
		super();
	}

	@Test
	public void testRemainingMemory() throws CardException {
		CommandAPDU apdu = new CommandAPDU(
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_GET_REMAINING_MEMORY, 0, 0);

		ResponseAPDU response = channel.transmit(apdu);

		commandSuccessful(response);
	}
}
