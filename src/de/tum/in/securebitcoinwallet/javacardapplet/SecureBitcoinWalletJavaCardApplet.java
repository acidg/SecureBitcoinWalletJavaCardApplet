package de.tum.in.securebitcoinwallet.javacardapplet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.RandomData;

/**
 * This is the SecureBitcoinWallet Applet. It stores the users private keys in a
 * map of bitcoin address to encrypted private key. To access the key store, a
 * pin is required which is set during setup. If the PIN is entered wrong too
 * many times, the card is locked and can only be unlocked, if the PUK is
 * provided.
 * 
 * @author Benedikt Schlagberger
 */
public class SecureBitcoinWalletJavaCardApplet extends Applet {
	/**
	 * Size of the PUK.
	 */
	public final static byte PUK_SIZE = 8;

	/**
	 * Retry limit for the PUK.
	 */
	public final static byte PUK_RETRIES = 5;

	/**
	 * Retry limit for the PIN.
	 */
	public final static byte PIN_RETRIES = 3;

	/**
	 * Minimum size of the PIN.
	 */
	public final static byte PIN_MINIMUM_SIZE = 4;

	/**
	 * Maximum size of the PIN.
	 */
	public final static byte PIN_MAXIMUM_SIZE = 8;

	/**
	 * The preset default pin.
	 */
	public final static byte[] DEFAULT_PIN = { (byte) 0x01, (byte) 0x02,
			(byte) 0x03, (byte) 0x04 };

	/**
	 * The size of the {@link KeyStore} of this applet in number of keys.
	 */
	public final static byte STORE_SIZE = (byte) 16;

	/**
	 * Maximum size of an address in bytes. 35 alpha numeric characters.
	 */
	public final static byte ADDRESS_SIZE = (byte) 35;

	/**
	 * Sign mode initialize.
	 */
	public final static byte SIGN_MODE_INIT = (byte) 0x01;

	/**
	 * Sign mode update.
	 */
	public final static byte SIGN_MODE_UPDATE = (byte) 0x02;

	/**
	 * Sign mode finalize.
	 */
	public final static byte SIGN_MODE_FINAL = (byte) 0x03;

	/**
	 * For the setup function which should only be called once.
	 */
	private boolean setupDone = false;

	/**
	 * PUK to authorize administrative operations like a pin reset if the retry
	 * limit is reached.
	 */
	private OwnerPIN puk;

	/**
	 * PIN to authorize user operations.
	 */
	private OwnerPIN pin;

	/**
	 * The {@link KeyStore} object of this Applet holding the private keys.
	 */
	private KeyStore keyStore;

	/**
	 * Buffer used to store the sha256 hash. See
	 * {@link #signSHA256Hash(APDU, byte[])}.
	 */
	private byte[] sha256TransactionHash;

	/**
	 * Constructor. Should initialize needed memory to prevent out of memory
	 * during runtime. Only this class's install method should create the applet
	 * object.
	 */
	private SecureBitcoinWalletJavaCardApplet() {
		puk = new OwnerPIN(PUK_RETRIES, PUK_SIZE);

		pin = new OwnerPIN(PIN_RETRIES, PIN_MAXIMUM_SIZE);
		pin.update(DEFAULT_PIN, (byte) 0, (byte) DEFAULT_PIN.length);

		keyStore = new KeyStore(STORE_SIZE, ADDRESS_SIZE);

		sha256TransactionHash = new byte[32];

		register();
	}

	/**
	 * Installs this applet.
	 *
	 * @param bArray The array containing installation parameters
	 * @param bOffset The starting offset in bArray
	 * @param bLength The length in bytes of the parameter data in bArray
	 */
	public static void install(byte bArray[], short bOffset, byte bLength)
			throws ISOException {
		new SecureBitcoinWalletJavaCardApplet();
	}

	/**
	 * Processes APDU commands from the host.
	 * 
	 * @param apdu The APDU command to process.
	 */
	public void process(APDU apdu) throws ISOException {

		byte[] buffer = apdu.getBuffer();

		if (selectingApplet()) {
			return;
		}

		// Verify the CLA byte
		if (buffer[ISO7816.OFFSET_CLA] != AppletInstructions.SECURE_BITCOIN_WALLET_CLA) {
			ISOException.throwIt(StatusCodes.CLA_NOT_SUPPORTED);
		}

		if (buffer[ISO7816.OFFSET_INS] == AppletInstructions.INS_SETUP) {
			setup(apdu, buffer);
			return;
		}

		if (!setupDone) {
			ISOException.throwIt(StatusCodes.CONDITIONS_NOT_SATISFIED);
		}

		// Check the INS byte
		switch (buffer[ISO7816.OFFSET_INS]) {
		case AppletInstructions.INS_UNLOCK:
			unlock(apdu, buffer);
			break;
		case AppletInstructions.INS_AUTHENTICATE:
			authenticate(apdu, buffer);
			break;
		case AppletInstructions.INS_CHANGE_PIN:
			changePin(apdu, buffer);
			break;
		case AppletInstructions.INS_PIN_VALIDATED:
			isPinValidated(apdu, buffer);
			break;
		case AppletInstructions.INS_SELECT_KEY:
			selectKey(apdu, buffer);
			break;
		case AppletInstructions.INS_SIGN_SHA256_HASH:
			signSHA256Hash(apdu, buffer);
			break;
		case AppletInstructions.INS_GENERATE_KEY:
			generateKey(apdu, buffer);
			break;
		case AppletInstructions.INS_IMPORT_PRIVATE_KEY:
			importPrivateKey(apdu, buffer);
			break;
		case AppletInstructions.INS_GET_PRIVATE_KEY:
			getPrivateKey(apdu, buffer);
			break;
		case AppletInstructions.INS_DELETE_PRIVATE_KEY:
			deletePrivateKey(apdu, buffer);
			break;
		case AppletInstructions.INS_GET_REMAINING_MEMORY:
			getRemainingMemory(apdu, buffer);
			break;
		default:
			ISOException.throwIt(StatusCodes.INS_NOT_SUPPORTED);
		}
	}

	/**
	 * Setup of the card. Generates and returns the PUK to reset the PIN.
	 * 
	 * <pre>
	 * INS: 0x02
	 * P1: 0x00
	 * P2: 0x00
	 * </pre>
	 * 
	 * Return: The generated PUK
	 */
	private void setup(APDU apdu, byte[] buffer) {
		if (setupDone) {
			ISOException.throwIt(StatusCodes.COMMAND_NOT_ALLOWED);
		}

		RandomData.getInstance(RandomData.ALG_SECURE_RANDOM).generateData(
				buffer, (short) 0, PUK_SIZE);
		puk.update(buffer, (short) 0, PUK_SIZE);

		setupDone = true;

		apdu.setOutgoingAndSend((short) 0, PUK_SIZE);
	}

	/**
	 * Unlocks the card, if the PIN has been entered wrong too many times.
	 * 
	 * <pre>
	 * INS:	0x04
	 * P1:	PUK length
	 * P2:	new PIN length
	 * Lc:	total length in bytes (P1 + P2)
	 * Data:	PUK and new PIN
	 * </pre>
	 */
	private void unlock(APDU apdu, byte[] buffer) {
		if (buffer[ISO7816.OFFSET_P1] != PUK_SIZE
				|| buffer[ISO7816.OFFSET_P2] < PIN_MINIMUM_SIZE
				|| buffer[ISO7816.OFFSET_P2] > PIN_MAXIMUM_SIZE) {
			ISOException.throwIt(StatusCodes.INCORRECT_P1P2);
		}

		if (apdu.setIncomingAndReceive() == 0) {
			ISOException.throwIt(StatusCodes.DATA_INVALID);
		}

		if (!puk.check(buffer, ISO7816.OFFSET_CDATA, buffer[ISO7816.OFFSET_P1])) {
			ISOException.throwIt(StatusCodes.AUTH_FAILED);
		} else {
			pin.resetAndUnblock();
			puk.reset();
			short newPinOffset = (short) (ISO7816.OFFSET_CDATA + buffer[ISO7816.OFFSET_P1]);
			pin.update(buffer, newPinOffset, buffer[ISO7816.OFFSET_P2]);
		}
	}

	/**
	 * Authenticates the user via the pin.
	 * 
	 * <pre>
	 * INS:	0x06
	 * P1:	0x00
	 * P2:	0x00
	 * Lc:	PIN length in bytes
	 * Data:	PIN itself
	 * </p>
	 */
	private void authenticate(APDU apdu, byte[] buffer) {
		pin.reset();

		if (buffer[ISO7816.OFFSET_P1] != 0x00
				|| buffer[ISO7816.OFFSET_P1] != 0x00) {
			ISOException.throwIt(StatusCodes.INCORRECT_P1P2);
		}

		if (pin.getTriesRemaining() == (byte) 0x00) {
			ISOException.throwIt(StatusCodes.CARD_LOCKED);
		}

		if (apdu.setIncomingAndReceive() == 0) {
			ISOException.throwIt(StatusCodes.DATA_INVALID);
		}

		if (!pin.check(buffer, ISO7816.OFFSET_CDATA, buffer[ISO7816.OFFSET_LC])) {
			ISOException.throwIt(StatusCodes.AUTH_FAILED);
		}
	}

	/**
	 * Changes the PIN. The User has to be authenticated.
	 * 
	 * <pre>
	 * INS:	0x08
	 * P1: 	0x00
	 * P2: 	0x00 
	 * Lc: 	length of PIN
	 * Data:	PIN itself
	 * </pre>
	 */
	private void changePin(APDU apdu, byte[] buffer) {
		if (!pin.isValidated()) {
			ISOException.throwIt(StatusCodes.PIN_VERIFICATION_REQUIRED);
		}

		byte pin_size = buffer[ISO7816.OFFSET_LC];

		if (pin_size < PIN_MINIMUM_SIZE || pin_size > PIN_MAXIMUM_SIZE) {
			ISOException.throwIt(StatusCodes.WRONG_LENGTH);
		}

		if (apdu.setIncomingAndReceive() == 0) {
			ISOException.throwIt(StatusCodes.DATA_INVALID);
		}

		pin.update(buffer, (short) (ISO7816.OFFSET_CDATA), pin_size);
		pin.reset();
	}

	/**
	 * Checks whether the PIN is validated.
	 * 
	 * <pre>
	 * INS:	0x0A
	 * P1:	0x00 
	 * P2:	0x00
	 * 
	 * Return: 0x01 if the PIN is validated, 0x00 otherwise.
	 * </pre>
	 */
	private void isPinValidated(APDU apdu, byte[] buffer) {
		buffer[0] = pin.isValidated() ? (byte) 1 : (byte) 0;

		apdu.setOutgoingAndSend((short) 0, (short) 1);
	}

	/**
	 * Selects the key specified by the given address. Used to sign a
	 * transaction.
	 * 
	 * <pre>
	 * INS:	0x0C 
	 * P1:	0x00 
	 * P2:	0x00 
	 * Lc:	length of address in bytes
	 * Data:	bitcoin address
	 * </pre>
	 */
	private void selectKey(APDU apdu, byte[] buffer) {
		if (!pin.isValidated()) {
			ISOException.throwIt(StatusCodes.PIN_VERIFICATION_REQUIRED);
		}

		if (apdu.setIncomingAndReceive() == 0) {
			ISOException.throwIt(StatusCodes.DATA_INVALID);
		}

		keyStore.selectKeyForSignature(buffer, ISO7816.OFFSET_CDATA,
				buffer[ISO7816.OFFSET_LC]);
	}

	/**
	 * Sign the given SHA256Hash of a Bitcoin transcation with the corresponding
	 * private key of the previously selected key, see: {@link #selectKey()}.
	 * 
	 * <pre>
	 * INS:	0x0E
	 * P1:	0x00
	 * P2:	0x00
	 * Lc:	Length of hash, should be 32 bytes.
	 * Data: SHA256 hash of the Bitcoin transcation
	 * 
	 * Return: The signature of the given hash.
	 * </pre>
	 */
	private void signSHA256Hash(APDU apdu, byte[] buffer) {
		if (!pin.isValidated()) {
			ISOException.throwIt(StatusCodes.PIN_VERIFICATION_REQUIRED);
		}

		if (buffer[ISO7816.OFFSET_P1] != 0x00
				|| buffer[ISO7816.OFFSET_P2] != 0x00) {
			ISOException.throwIt(StatusCodes.INCORRECT_P1P2);
		}

		if ((buffer[ISO7816.OFFSET_LC] & 0xFF) != 0x20) {
			ISOException.throwIt(StatusCodes.WRONG_LENGTH);
		}

		if (apdu.setIncomingAndReceive() != (short) sha256TransactionHash.length) {
			ISOException.throwIt(StatusCodes.DATA_INVALID);
		}

		Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, sha256TransactionHash,
				(short) 0, buffer[ISO7816.OFFSET_LC]);

		apdu.setOutgoingAndSend((short) 0, keyStore.signMessage(buffer,
				ISO7816.OFFSET_CDATA, buffer[ISO7816.OFFSET_LC], buffer,
				(short) 0));
	}

	/**
	 * Generates a new private and public keypair. The private key is stored
	 * inside the keystore. The public key is returned.
	 *
	 * <pre>
	 * INS:	0x20
	 * P1:	0x00
	 * P2:	0x00
	 * 
	 * Return: The generated public key
	 * </pre>
	 */
	private void generateKey(APDU apdu, byte[] buffer) {
		if (!pin.isValidated()) {
			ISOException.throwIt(StatusCodes.PIN_VERIFICATION_REQUIRED);
		}

		if ((buffer[ISO7816.OFFSET_P1] & 0xFF) != 0x00
				|| (buffer[ISO7816.OFFSET_P2] & 0xFF) != 0x00) {
			ISOException.throwIt(StatusCodes.INCORRECT_P1P2);
		}

		apdu.setOutgoingAndSend((short) 0,
				keyStore.generateKeyPair(buffer, (short) 0));
	}

	/**
	 * Stores the given private key encrypted in the EEPROM.
	 * 
	 * <pre>
	 * INS:	0x22
	 * P1:	length of address in bytes
	 * P2:	length of private key in bytes
	 * Lc:	total length
	 * Data:	[address + privateKey]
	 * 
	 * Return: The address for which the key is stored, if the operation was
	 * successful.
	 * </pre>
	 * 
	 */
	private void importPrivateKey(APDU apdu, byte[] buffer) {
		if (!pin.isValidated()) {
			ISOException.throwIt(StatusCodes.PIN_VERIFICATION_REQUIRED);
		}

		if (((short) (buffer[ISO7816.OFFSET_P1] & 0xFF)) > ((short) ADDRESS_SIZE & 0xFF)) {
			ISOException.throwIt(StatusCodes.WRONG_ADDRESS_LENGTH);
		}
		
		if (buffer[ISO7816.OFFSET_P2] != (byte) 0x20) {
			ISOException.throwIt(StatusCodes.WRONG_PRIVATE_KEY_LENGTH);
		}

		if (apdu.setIncomingAndReceive() == 0) {
			ISOException.throwIt(StatusCodes.DATA_INVALID);
		}

		keyStore.importPrivateKey(buffer, (short) ISO7816.OFFSET_CDATA,
				(short) buffer[ISO7816.OFFSET_P1],
				(short) (ISO7816.OFFSET_CDATA + buffer[ISO7816.OFFSET_P1]),
				(short) buffer[ISO7816.OFFSET_P2]);
	}

	/**
	 * Gets the encrypted private key.
	 * 
	 * <pre>
	 * INS:	0x24
	 * P1:	0x00
	 * P2:	0x00
	 * Lc:	Length of Bitcoin address
	 * Data:	Bitcoin address for which the encrypted key should be fetched.
	 * 
	 * Return: The encrypted private key for the given address
	 * </pre>
	 */
	private void getPrivateKey(APDU apdu, byte[] buffer) {
		if (!pin.isValidated()) {
			ISOException.throwIt(StatusCodes.PIN_VERIFICATION_REQUIRED);
		}

		if (apdu.setIncomingAndReceive() == 0) {
			ISOException.throwIt(StatusCodes.DATA_INVALID);
		}

		if (((short) (buffer[ISO7816.OFFSET_LC] & 0xFF)) > ((short) ADDRESS_SIZE & 0xFF)) {
			ISOException.throwIt(StatusCodes.WRONG_ADDRESS_LENGTH);
		}

		apdu.setOutgoingAndSend((short) 0, keyStore.getEncryptedPrivateKey(
				buffer, (short) ISO7816.OFFSET_CDATA, (short) buffer[ISO7816.OFFSET_LC],
				buffer, (short) 0));
	}

	/**
	 * Deletes the private key for the given address.
	 * 
	 * <pre>
	 * INS:	0x26
	 * P1:	0x00
	 * P2:	0x00
	 * Lc:	Length of address
	 * Data:	Address for which the private key should be deleted.
	 * </pre>
	 */
	private void deletePrivateKey(APDU apdu, byte[] buffer) {
		if (!pin.isValidated()) {
			ISOException.throwIt(StatusCodes.PIN_VERIFICATION_REQUIRED);
		}

		if (apdu.setIncomingAndReceive() == 0) {
			ISOException.throwIt(StatusCodes.DATA_INVALID);
		}

		keyStore.deletePrivateKey(buffer, ISO7816.OFFSET_CDATA,
				buffer[ISO7816.OFFSET_LC]);
	}

	/**
	 * Returns the remaining memory in keys.
	 * 
	 * <pre>
	 * INS:	0x28
	 * P1:	0x00
	 * P2:	0x00
	 * Lc:	0x00
	 * 
	 * Return: The remaining memory in keys.
	 * </pre>
	 */
	private void getRemainingMemory(APDU apdu, byte[] buffer) {
		Util.setShort(buffer, (short) 0, keyStore.getNumberOfKeysRemaining());

		apdu.setOutgoingAndSend((short) 0, (short) 2);
	}
}