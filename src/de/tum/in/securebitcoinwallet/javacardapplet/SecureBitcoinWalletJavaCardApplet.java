package de.tum.in.securebitcoinwallet.javacardapplet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;
import javacard.security.RandomData;

/**
 * This is the SecureBitcoinWallet Applet. It stores the users private keys in a
 * map of bitcoin address to encrypted private key.
 * To access the key store, a pin is required which is set during setup. If the
 * PIN is entered wrong too many times, the card is locked and can only be
 * unlocked, if the PUK is provided.
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
	 * For the setup function which should only be called once.
	 */
	private boolean setupDone = false;

	/**
	 * PUK to authorize administrative operations like a pin reset if the
	 * retry limit is reached.
	 */
	private OwnerPIN puk;

	/**
	 * PIN to authorize user operations.
	 */
	private OwnerPIN pin;

	/**
	 * Constructor. Should initialize needed memory to prevent out of memory
	 * during runtime. Only this class's install method should create the applet
	 * object.
	 */
	private SecureBitcoinWalletJavaCardApplet() {
		puk = new OwnerPIN(PUK_RETRIES, PUK_SIZE);

		pin = new OwnerPIN(PIN_RETRIES, PIN_MAXIMUM_SIZE);
		pin.update(DEFAULT_PIN, (byte) 0, (byte) DEFAULT_PIN.length);

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
	@Override
	public void process(APDU apdu) throws ISOException {
		byte[] buffer = apdu.getBuffer();

		if (selectingApplet()) {
			return;
		}

		// Verify the CLA byte
		if (buffer[ISO7816.OFFSET_CLA] != AppletInstructions.SECURE_BITCOIN_WALLET_CLA) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}

		if (buffer[ISO7816.OFFSET_INS] == AppletInstructions.INS_SETUP) {
			setup(apdu, buffer);
			return;
		}

		if (!setupDone) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
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
		case AppletInstructions.INS_PUT_PRIVATE_KEY:
			putPrivateKey(apdu, buffer);
			break;
		case AppletInstructions.INS_GET_PRIVATE_KEY:
			getPrivateKey(apdu, buffer);
			break;
		case AppletInstructions.INS_DELETE_PRIVATE_KEY:
			deletePrivateKey(apdu, buffer);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	/**
	 * Setup of the card. Generates and returns the PUK to reset the PIN.
	 * 
	 * INS: 0x02
	 * P1: 0x00
	 * P2: 0x00
	 * 
	 * Return: The generated PUK
	 */
	private void setup(APDU apdu, byte[] buffer) {
		if (setupDone) {
			ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
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
	 * INS: 0x04
	 * P1: PUK length
	 * P2: new PIN length
	 * Lc: total length in bytes (P1 + P2)
	 * Data: PUK and new PIN
	 */
	private void unlock(APDU apdu, byte[] buffer) {
		if (buffer[ISO7816.OFFSET_P1] != PUK_SIZE
				|| buffer[ISO7816.OFFSET_P2] < PIN_MINIMUM_SIZE
				|| buffer[ISO7816.OFFSET_P2] > PIN_MAXIMUM_SIZE) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}

		if (!puk.check(buffer, ISO7816.OFFSET_CDATA, buffer[ISO7816.OFFSET_P1])) {
			ISOException.throwIt(StatusCodes.SW_AUTH_FAILED);
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
	 * INS: 0x04
	 * P1: 0x00
	 * P2: 0x00
	 * Lc: PIN length in bytes
	 * Data: PIN itself
	 */
	private void authenticate(APDU apdu, byte[] buffer) {
		pin.reset();

		if (buffer[ISO7816.OFFSET_P1] != 0x00
				|| buffer[ISO7816.OFFSET_P1] != 0x00) {
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		}

		if (pin.getTriesRemaining() == (byte) 0x00) {
			ISOException.throwIt(StatusCodes.SW_CARD_LOCKED);
		}

		if (apdu.setIncomingAndReceive() == 0) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}

		if (!pin.check(buffer, ISO7816.OFFSET_CDATA, buffer[ISO7816.OFFSET_LC])) {
			ISOException.throwIt(StatusCodes.SW_AUTH_FAILED);
		}
	}

	/**
	 * Changes the PIN. The User has to be authenticated.
	 * 
	 * INS: 0x06
	 * P1: 0x00
	 * P2: 0x00
	 * Lc: length of PIN
	 * Data: PIN istself
	 */
	private void changePin(APDU apdu, byte[] buffer) {
		if (!pin.isValidated()) {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}

		apdu.setIncomingAndReceive();

		byte pin_size = buffer[ISO7816.OFFSET_LC];

		if (pin_size < 4) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}

		pin.update(buffer, (short) (ISO7816.OFFSET_CDATA), pin_size);
		pin.reset();
	}

	private void isPinValidated(APDU apdu, byte[] buffer) {
		buffer[0] = pin.isValidated() ? (byte) 1 : (byte) 0;

		apdu.setOutgoingAndSend((short) 0, (short) 1);
	}

	/**
	 * Stores the given private key encrypted in the EEPROM.
	 * 
	 * INS: 0xD8
	 * P1: length of address in bytes
	 * P2: length of private key in
	 * bytes Lc: total length
	 * Data: address and private key
	 * 
	 * Return: The address for which the key is stored, if the operation was
	 * successful.
	 */
	private void putPrivateKey(APDU apdu, byte[] buffer) {
		if (!pin.isValidated()) {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}

	}

	private void getPrivateKey(APDU apdu, byte[] buffer) {
		// TODO Auto-generated method stub

	}

	private void deletePrivateKey(APDU apdu, byte[] buffer) {
		// TODO Auto-generated method stub

	}
}
