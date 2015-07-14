package de.tum.in.securebitcoinwallet.javacardapplet.test.tests;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import de.tum.in.securebitcoinwallet.javacardapplet.AppletInstructions;
import de.tum.in.securebitcoinwallet.javacardapplet.SecureBitcoinWalletJavaCardApplet;
import de.tum.in.securebitcoinwallet.javacardapplet.test.util.TestUtils;

public class KeyStoreTest extends AppletTestBase {
	protected final static String BITCOIN_ADDRESS_STRING = "1P4nqAMxhF6PobyiDYm5jcUZd4CWPsGUy4";
	protected final static String PRIVATE_KEY_HEX = "a5559c3f2f69a649617e57a78972c77aa4a309b3c413db24e0533495d9b93ae4";
	protected final static String PUBLIC_KEY_HEX = "048d03747cf848dfb5384223c7128a95bc856a9741584d08cd4baa0db9ae895e49fb273edf7e99b7ced6cb2c732a1481727abb9b6f5ff9c28370f4f654645a9c53";

	/**
	 * Text used for checking the signature.
	 */
	private static final String HASHABLE_TEXT = "SecureBitcoinWallet";

	public KeyStoreTest() throws CardException {
		super();
	}

	/**
	 * Tests the import and delete key function.
	 * 
	 * @throws CardException
	 */
	@Test
	public void testKeyImportAndDelete() throws CardException {
		assertTrue(authenticate(SecureBitcoinWalletJavaCardApplet.DEFAULT_PIN));

		byte[] rawBitcoinAddress = BITCOIN_ADDRESS_STRING.getBytes();
		byte[] rawPrivateKey = Hex.decode(PRIVATE_KEY_HEX);

		importKey(rawBitcoinAddress, rawPrivateKey);

		deleteKey(rawBitcoinAddress);
	}

	/**
	 * Tests the key generation function.
	 * 
	 * @throws CardException
	 */
	@Test
	public void testKeyGenerator() throws CardException {
		assertTrue(authenticate(SecureBitcoinWalletJavaCardApplet.DEFAULT_PIN));

		CommandAPDU generateKeyInstruction = new CommandAPDU(
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_GENERATE_KEY, 0, 0);

		ResponseAPDU response = smartCard.transmit(generateKeyInstruction);
		assertTrue(commandSuccessful(response));
		
		byte[] publicKey = response.getData();
		
		System.out.println(TestUtils.getHexString(publicKey));
		
		assertTrue(publicKey.length == 65);
		assertTrue(publicKey[0] == 4);
		
		assertEquals(SecureBitcoinWalletJavaCardApplet.STORE_SIZE - 1, getRemainingSlots());
		
		deleteKey(TestUtils.calculateBitcoinAddress(publicKey).getBytes());
		
		assertEquals(SecureBitcoinWalletJavaCardApplet.STORE_SIZE, getRemainingSlots());
	}

	/**
	 * Tests the export function.
	 * 
	 * @throws CardException
	 */
	@Test
	public void testKeyExport() throws CardException {
		assertTrue(authenticate(SecureBitcoinWalletJavaCardApplet.DEFAULT_PIN));

		byte[] rawBitcoinAddress = BITCOIN_ADDRESS_STRING.getBytes();
		byte[] rawPrivateKey = Hex.decode(PRIVATE_KEY_HEX);
		
		importKey(rawBitcoinAddress, rawPrivateKey);

		CommandAPDU getKeyInstruction = new CommandAPDU(
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_GET_PRIVATE_KEY, 0x00, 0x00,
				rawBitcoinAddress);

		ResponseAPDU response = smartCard.transmit(getKeyInstruction);

		assertTrue(commandSuccessful(response));
		
		assertTrue(response.getData().length == 32);
		
		deleteKey(rawBitcoinAddress);
	}

	/**
	 * Deletes the encrypted private key specified by the given Bitcoin address.
	 * 
	 * @param bitcoinAddress
	 * @throws CardException
	 */
	private void deleteKey(byte[] rawBitcoinAddress) throws CardException {
		CommandAPDU deleteKeyInstruction = new CommandAPDU(
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_DELETE_PRIVATE_KEY, 0, 0,
				rawBitcoinAddress);

		ResponseAPDU response = smartCard.transmit(deleteKeyInstruction);

		assertTrue(commandSuccessful(response));
	}

	/**
	 * Imports the given private key with the given Bitcoin address
	 * 
	 * @param bitcoinAddress The Bitcoin address
	 * @param privateKey The private key
	 * @throws CardException
	 */
	private void importKey(byte[] bitcoinAddress, byte[] privateKey)
			throws CardException {
		CommandAPDU importKeyInstruction = new CommandAPDU(
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_IMPORT_PRIVATE_KEY,
				bitcoinAddress.length, privateKey.length,
				TestUtils.concatenate(bitcoinAddress, privateKey));

		ResponseAPDU response = smartCard.transmit(importKeyInstruction);
		assertTrue(commandSuccessful(response));
	}

	/**
	 * Signs a string with the smartcard and returns its signature.
	 * 
	 * @throws CardException
	 */
	private byte[] getSignature(byte[] bitcoinAddress, String input) throws CardException {
		selectPrivateKey(bitcoinAddress);
		
		byte[] hash = getSHA256Hash(input);

		CommandAPDU signInstruction = new CommandAPDU(
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_SIGN_SHA256_HASH, 0, 0, hash);

		ResponseAPDU response = smartCard.transmit(signInstruction);
		assertTrue(commandSuccessful(response));

		return response.getData();
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

		ResponseAPDU response = smartCard.transmit(selectPrivateKeyInstruction);

		assertTrue(commandSuccessful(response));
	}
}
