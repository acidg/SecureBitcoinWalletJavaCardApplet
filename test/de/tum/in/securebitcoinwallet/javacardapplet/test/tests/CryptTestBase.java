package de.tum.in.securebitcoinwallet.javacardapplet.test.tests;

import static org.junit.Assert.assertTrue;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;

import de.tum.in.securebitcoinwallet.javacardapplet.AppletInstructions;
import de.tum.in.securebitcoinwallet.javacardapplet.SecureBitcoinWalletJavaCardApplet;

public abstract class CryptTestBase extends AppletTestBase {
	protected final static String BITCOIN_ADDRESS_STRING = "1P4nqAMxhF6PobyiDYm5jcUZd4CWPsGUy4";
	protected final static String PRIVATE_KEY_STRING = "5JY6U1SZMhUsWi7KCxo8frPTTSwDvd3VJ6Ma4t4T9aEiDLHV5gV";
	protected final static String PUBLIC_KEY_STRING = "048d03747cf848dfb5384223c7128a95bc856a9741584d08cd4baa0db9ae895e49fb273edf7e99b7ced6cb2c732a1481727abb9b6f5ff9c28370f4f654645a9c53";

	/**
	 * Initializes the KeyStore with a private key
	 * @throws CardException 
	 */
	public CryptTestBase() throws CardException {
		super();
		assertTrue(commandSuccessful(authenticate(SecureBitcoinWalletJavaCardApplet.DEFAULT_PIN)));

		CommandAPDU importKeyInstruction = new CommandAPDU(
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_IMPORT_PRIVATE_KEY,
				BITCOIN_ADDRESS_STRING.getBytes().length,
				PRIVATE_KEY_STRING.getBytes().length,
				(BITCOIN_ADDRESS_STRING + PRIVATE_KEY_STRING).getBytes());


		assertTrue(commandSuccessful(channel
				.transmit(importKeyInstruction).getBytes()));
	}
}
