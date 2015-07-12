package de.tum.in.securebitcoinwallet.javacardapplet.test.tests;

import static org.junit.Assert.assertTrue;

import java.io.UnsupportedEncodingException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javacard.security.ECPublicKey;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.junit.Test;

import de.tum.in.securebitcoinwallet.javacardapplet.AppletInstructions;
import de.tum.in.securebitcoinwallet.javacardapplet.SecureBitcoinWalletJavaCardApplet;

public class KeyStoreTest extends AppletTestBase {
	protected final static String BITCOIN_ADDRESS_STRING = "1P4nqAMxhF6PobyiDYm5jcUZd4CWPsGUy4";
	protected final static String PRIVATE_KEY_STRING = "5JY6U1SZMhUsWi7KCxo8frPTTSwDvd3VJ6Ma4t4T9aEiDLHV5gV";
	protected final static String PUBLIC_KEY_STRING = "048d03747cf848dfb5384223c7128a95bc856a9741584d08cd4baa0db9ae895e49fb273edf7e99b7ced6cb2c732a1481727abb9b6f5ff9c28370f4f654645a9c53";

	public KeyStoreTest() throws CardException {
		super();
		assertTrue(commandSuccessful(authenticate(SecureBitcoinWalletJavaCardApplet.DEFAULT_PIN)));
	}

	/**
	 * Text used for checking the signature.
	 */
	private static final String HASHABLE_TEXT = "SecureBitcoinWallet";

	/**
	 * Tests the import key function.
	 * 
	 * @throws CardException
	 */
	@Test
	public void testKeyImport() throws CardException {
		getSignature(HASHABLE_TEXT);
		CommandAPDU importKeyInstruction = new CommandAPDU(
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_IMPORT_PRIVATE_KEY,
				BITCOIN_ADDRESS_STRING.getBytes().length,
				PRIVATE_KEY_STRING.getBytes().length,
				(BITCOIN_ADDRESS_STRING + PRIVATE_KEY_STRING).getBytes());

		ResponseAPDU response = smartCard.transmit(importKeyInstruction);

		assertTrue(commandSuccessful(response));

		byte[] signature = getSignature(HASHABLE_TEXT);

		ECPublicKey publicKey;
		try {
			publicKey = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(
					new X509EncodedKeySpec(PUBLIC_KEY_STRING.getBytes()));
		} catch (InvalidKeySpecException e) {
			throw new RuntimeException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}

		verifySignature(HASHABLE_TEXT, signature, publicKey);
	}
	
	/**
	 * Tests the key generation function.
	 * 
	 * @throws CardException
	 */
	@Test
	public void testKeyGenerator() throws CardException {
		CommandAPDU generateKeyInstruction = new CommandAPDU(
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_IMPORT_PRIVATE_KEY,
				BITCOIN_ADDRESS_STRING.getBytes().length,
				PRIVATE_KEY_STRING.getBytes().length,
				(BITCOIN_ADDRESS_STRING + PRIVATE_KEY_STRING).getBytes());
		
		ResponseAPDU response = smartCard.transmit(generateKeyInstruction);
		
		assertTrue(commandSuccessful(response));
		
		// TODO more testing
	}
	
	/**
	 * Tests the export function.
	 * @throws CardException 
	 */
	@Test
	public void testKeyExport() throws CardException {
		CommandAPDU getKeyInstruction = new CommandAPDU(
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_GET_PRIVATE_KEY,0x00, 0x00,
				BITCOIN_ADDRESS_STRING.getBytes());
		
		ResponseAPDU response = smartCard.transmit(getKeyInstruction);
		
		assertTrue(commandSuccessful(response));
		
		// TODO more testing
	}

	/**
	 * Verifies the given signature.
	 * 
	 * @param hashableText The text for which the sha256 hash has been
	 *            calculated
	 * @param signature The signature of the sha256 hash of the text
	 * @param publicKey The public key to verify the singature
	 */
	private void verifySignature(String hashableText, byte[] signature,
			ECPublicKey publicKey) {
		// TODO implement
	}

	/**
	 * Signs a string with the smartcard and returns its signature.
	 * 
	 * @throws CardException
	 */
	private byte[] getSignature(String input) throws CardException {
		byte[] hash = getSHA256Hash(input);

		CommandAPDU signInstruction = new CommandAPDU(
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_SIGN_SHA256_HASH, 0, 0, hash);

		selectPrivateKey(BITCOIN_ADDRESS_STRING.getBytes());

		ResponseAPDU response = smartCard.transmit(signInstruction);
		return response.getBytes();
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
		
		ResponseAPDU response = smartCard
				.transmit(selectPrivateKeyInstruction);
		
		assertTrue(commandSuccessful(response));
	}
}
