package de.tum.in.securebitcoinwallet.javacardapplet.test.tests;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.junit.Test;

import de.tum.in.securebitcoinwallet.javacardapplet.AppletInstructions;

public class KeyStoreTest extends CryptTestBase {
	private static final String HASHABLE_TEXT = "SecureBitcoinWallet";

	/**
	 * Checks whether the imported key is usable
	 */
	@Test
	public void testKeyImport() {
		testSignature();
	}

	/**
	 * Signs a string with the smartcard and checks whether the signature is
	 * valid.
	 */
	private void testSignature() {
		byte[] hash = getSHA256Hash(HASHABLE_TEXT);

		byte[] signInstructionHeader = {
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_SIGN_SHA256_HASH, 0x00, 0x00
		};
		
		// TODO implement
	}

	/**
	 * Calculates the SHA256 hash for the given string
	 * 
	 * @param text The text for which the hash should be generated.
	 */
	private byte[] getSHA256Hash(String text) {
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("SHA-256 algorithm not found!");
		}

		try {
			md.update(text.getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException("UTF-8 encoding not supported!");
		}

		return md.digest();
	}

}
