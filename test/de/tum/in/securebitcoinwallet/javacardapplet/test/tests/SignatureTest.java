package de.tum.in.securebitcoinwallet.javacardapplet.test.tests;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.junit.Test;

import de.tum.in.securebitcoinwallet.javacardapplet.AppletInstructions;

public class SignatureTest extends CryptTestBase {
	@Test
	public void testSHA256Sign() throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] sha256Hash = md.digest(new String("somestring").getBytes());

		byte[] apduHeader = { AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_SIGN_SHA256_HASH, (byte) 0x00,
				(byte) 0x00, (byte) 0x20 };

		byte[] apdu = new byte[sha256Hash.length + apduHeader.length];
		
		// assemble apdu
		for (int i = 0; i < apduHeader.length; i++) {
			apdu[i] = apduHeader[i];
		}
		
		for (int i = 0; i < sha256Hash.length; i++) {
			apdu[i + apduHeader.length] = sha256Hash[i];
		}
		
		byte[] response = simulator.transmitCommand(apdu);
		System.out.println(response);
	}
}
