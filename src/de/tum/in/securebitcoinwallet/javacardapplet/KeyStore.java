package de.tum.in.securebitcoinwallet.javacardapplet;

import javacard.security.AESKey;
import javacard.security.ECPrivateKey;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

/**
 * Storage for private keys. Uses two arrays to store the private key and a
 * mapping array with addresses. The mapping array is used to easily find the
 * private key for a given address.
 * 
 * @author Benedikt Schlagberger
 */
public class KeyStore {

	/**
	 * AES encryption used for encrypting the private key for export.
	 */
	private static final byte AES_ENCRYPTION_MODE = Cipher.ALG_AES_BLOCK_128_CBC_NOPAD;

	/**
	 * Length of the AES key.
	 */
	private static final short AES_KEY_LENGTH = KeyBuilder.LENGTH_AES_128;

	/**
	 * Length of the elliptic curve private key. Bitcoin uses 256 bits.
	 */
	private static final short PRIVATE_KEY_LENGTH = KeyBuilder.LENGTH_EC_FP_256;

	/**
	 * The store for the private keys. If a key is null, the slot is free and
	 * can be used for a new key. This should be kept in sync with
	 * {@link #addressToKeyIndexMap}.
	 */
	private ECPrivateKey[] keys;

	/**
	 * Map to find the key for a specified address. Maps addresses to the index
	 * of the corresponding private key inside the {@link keys} array.
	 */
	private BitcoinAddress[] addressToKeyIndexMap;

	/**
	 * Key used for encryption of the private keys. Generated randomly during
	 * instantiation of this KeyStore.
	 */
	private AESKey aesKey;

	/**
	 * Cipher used for AES encryption of the private keys.
	 */
	private Cipher aesCipher;

	/**
	 * Index of the key inside the {@link keys} array.
	 */
	private short addressIndex;

	/**
	 * Buffer used to encrypt private keys.
	 */
	private byte[] encryptionBuffer;

	/**
	 * Constructor. Has to be called inside the constructor of the applet to
	 * reserve needed memory.
	 * 
	 * @param storeSize The size of the keystore in keys. Maximum is 254 (0xFE).
	 *            If a storeSize bigger than 254 is provided, the size will be
	 *            set to 254.
	 * @param addressSize The maximum size of an address in bytes. Maximum is
	 *            254. If the maximum is exceeded, the maximum of 254 is used
	 *            instead.
	 */
	public KeyStore(short storeSize, short addressSize) {
		addressIndex = 0;

		if (storeSize >= 0xFF) {
			storeSize = 0xFE;
		}

		if (addressSize >= 0xFF) {
			addressSize = 0xFE;
		}

		encryptionBuffer = new byte[PRIVATE_KEY_LENGTH / 8];

		byte[] randomData = new byte[AES_KEY_LENGTH / 8];
		RandomData.getInstance(RandomData.ALG_SECURE_RANDOM).generateData(
				randomData, (short) 0, (byte) randomData.length);

		aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES,
				AES_KEY_LENGTH, false);
		aesKey.setKey(randomData, (short) 0);

		aesCipher = Cipher.getInstance(AES_ENCRYPTION_MODE, false);

		keys = new ECPrivateKey[storeSize];

		addressToKeyIndexMap = new BitcoinAddress[storeSize];
		// Allocate memory for addresses
		for (short i = 0; i < addressToKeyIndexMap.length; i++) {
			addressToKeyIndexMap[i] = new BitcoinAddress(addressSize);
		}

		// Allocate memory for keys
		for (short i = 0; i < keys.length; i++) {
			keys[i] = (ECPrivateKey) KeyBuilder.buildKey(
					KeyBuilder.TYPE_EC_FP_PRIVATE, PRIVATE_KEY_LENGTH,
					false);

		}
	}

	/**
	 * Stores the given private key in the key store.
	 * 
	 * @param src The byte array, in which the address and private key can be
	 *            found.
	 * @param addrOff Offset for the address inside the byte array
	 * @param addrLength Length of the address
	 * @param keyOff Offset of the private key inside the byte array
	 * @param keyLength Length of the private key
	 * 
	 * @return True, if the key could be saved, false if the store is full, the
	 *         address is too long or the address is already in the key store.
	 */
	public boolean putPrivateKey(byte[] src, short addrOff, byte addrLength,
			short keyOff, byte keyLength) {
		findFirstFreePosition();
		if (addressIndex == 0xFF
				|| addrLength > addressToKeyIndexMap[0].getSize()) {
			return false;
		}

		// Init key with parameters
		keys[addressIndex].setFieldFP(SECP256K1.P, (short) 0,
				(short) SECP256K1.P.length);
		keys[addressIndex].setA(SECP256K1.a, (short) 0,
				(short) SECP256K1.a.length);
		keys[addressIndex].setB(SECP256K1.b, (short) 0,
				(short) SECP256K1.b.length);
		keys[addressIndex].setG(SECP256K1.G, (short) 0,
				(short) SECP256K1.G.length);
		keys[addressIndex].setR(SECP256K1.R, (short) 0,
				(short) SECP256K1.R.length);
		keys[addressIndex].setK(SECP256K1.K);
		keys[addressIndex].setS(src, keyOff, keyLength);

		// Add length of address to mapping array
		addressToKeyIndexMap[addressIndex].setAddress(src, addrOff, addrLength);
		return true;
	}

	/**
	 * Retireves the encrypted private key for the given Bitcoin address.
	 * 
	 * @param src The byte array, in which the address and private key can be
	 *            found.
	 * @param addrOff Offset for the address inside the byte array
	 * @param addrLength Length of the address
	 * @param output The output buffer in which the encrypted key will be
	 *            written.
	 * @param outOff The offset inside the output buffer
	 * 
	 * @return The size of the encrypted key in bytes
	 */
	public short getEncryptedPrivateKey(byte[] src, short addrOff,
			byte addrLength, byte[] output, short outOff) {
		ECPrivateKey privateKey = getPrivateKey(src, addrOff, addrLength);

		privateKey.getS(encryptionBuffer, (short) 0);

		aesCipher.init(aesKey, Cipher.MODE_ENCRYPT);
		aesCipher.doFinal(encryptionBuffer, (short) 0,
				(short) encryptionBuffer.length, output, outOff);

		return (short) encryptionBuffer.length;
	}

	/**
	 * Deletes the private key for the given address. If the key could not be
	 * found, nothing is done.
	 * 
	 * @param src The byte array, in which the address and private key can be
	 *            found.
	 * @param addrOff Offset for the address inside the byte array
	 * @param addrLength Length of the address
	 */
	public void removePrivateKey(byte[] src, short addrOff, short addrLength) {
		calculateIndexForAddress(src, addrOff, addrLength);
		if (addressIndex != 0xFF) {
			addressToKeyIndexMap[addressIndex].delete();
			keys[addressIndex].clearKey();
		}
	}

	/**
	 * Calculates the index of the key for the given address in
	 * {@link #addressIndex}.
	 * 
	 * @param src The byte array in which the address can be found
	 * @param addrOff Offset of the address inside the given byte array
	 * @param addrLength Length of the address
	 */
	private void calculateIndexForAddress(byte[] src, short addrOff,
			short addrLength) {
		for (addressIndex = 0; addressIndex < addressToKeyIndexMap.length; addressIndex++) {
			if (addressToKeyIndexMap[addressIndex].equalsAddress(src, addrOff,
					addrLength)) {
				return;
			}
		}
		addressIndex = (byte) 0xFF;
	}

	/**
	 * Calculates the index of the first free slot inside the key array in
	 * {@link #addressIndex}. If no free slot could be found, addressIndex is
	 * set to 255 (0xFF).
	 */
	private void findFirstFreePosition() {
		for (addressIndex = 0; addressIndex < keys.length; addressIndex++) {
			if (!keys[addressIndex].isInitialized()) {
				return;
			}
		}
		addressIndex = (byte) 0xFF;
	}

	/**
	 * Returns the private key for the given address key, or null, if the key
	 * could not be found.
	 * 
	 * @param src The byte array in which the address can be found
	 * @param addrOff Offset of the address inside the given byte array
	 * @param addrLength Length of the address
	 * @param
	 * @param dest
	 * @return
	 */
	private ECPrivateKey getPrivateKey(byte[] src, short addrOff,
			short addrLength) {
		calculateIndexForAddress(src, addrOff, addrLength);
		if (addressIndex == 0xFF) {
			return null;
		}

		return keys[addressIndex];
	}
}
