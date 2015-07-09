package de.tum.in.securebitcoinwallet.javacardapplet.test.tests;

import static org.junit.Assert.assertTrue;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;

import org.junit.Test;

import de.tum.in.securebitcoinwallet.javacardapplet.AppletInstructions;

public class KeyStoreTest extends CryptTestBase {
	public KeyStoreTest() throws CardException {
		super();
	}

	private static final String HASHABLE_TEXT = "SecureBitcoinWallet";

	/**
	 * Checks whether the imported key is usable
	 * 
	 * @throws CardException
	 */
	@Test
	public void testKeyImport() throws CardException {
		testSignature();
	}

	/**
	 * Signs a string with the smartcard and checks whether the signature is
	 * valid.
	 * 
	 * @throws CardException
	 */
	private void testSignature() throws CardException {
		byte[] hash = getSHA256Hash(HASHABLE_TEXT);

		CommandAPDU signInstruction = new CommandAPDU(
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_SIGN_SHA256_HASH, 0, 0, hash);

		selectPrivateKey(BITCOIN_ADDRESS_STRING.getBytes());

		byte[] response = channel.transmit(signInstruction).getBytes();
		System.out.println(getHexString(response));
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

	/**
	 * Selects the given private key for signing.
	 * 
	 * @param bitcoinAddress The private key's Bitcoin address
	 * @throws CardException 
	 */
	private void selectPrivateKey(byte[] bitcoinAddress) throws CardException {
		CommandAPDU selectPrivateKeyInstruction = new CommandAPDU(
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_SELECT_KEY, 0, 0, bitcoinAddress);

		assertTrue(commandSuccessful(channel.transmit(
				selectPrivateKeyInstruction).getBytes()));
	}
}
