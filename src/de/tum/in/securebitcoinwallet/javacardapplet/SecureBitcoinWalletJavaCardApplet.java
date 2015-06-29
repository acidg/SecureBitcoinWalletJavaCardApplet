package de.tum.in.securebitcoinwallet.javacardapplet;

import javax.print.attribute.standard.MediaSize.ISO;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;

/**
 * For now, this class implements a hello world applet which just echos the
 * received commands.
 * 
 * @author Benedikt Schlagberger
 */
public class SecureBitcoinWalletJavaCardApplet extends Applet {
	/**
	 * Maximum number of pin retries.
	 */
	public final static byte PIN_RETRIES = 3;
	
	/**
	 * Maximum number of pin retries.
	 */
	public final static byte PIN_MAXIMUM_SIZE = 8;
	
	/**
	 * The preset default pin.
	 */
	public final static byte[] DEFAULT_PIN = { (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0xa4 };
	
	/**
	 * CLA instruction class for Secure Bitcoin Wallet app instructions.
	 */
	public final static byte SECURE_BITCOIN_WALLET_CLA = (byte) 0xA0;
	
	/**
	 * Setup Instruction.
	 */
	public final static byte INS_SETUP = (byte) 0x02;
	
	/**
	 * User authentication instruction.
	 */
	public static final byte INS_AUTHENTICATE = (byte) 0x04;
	
	/**
	 * Set pin instruction.
	 */
	public final static byte INS_CHANGE_PIN = (byte) 0x06;

	/**
	 * Pin validated instruction.
	 */
	public static final byte INS_PIN_VALIDATED = (byte) 0x08;

	/**
	 * The entered PIN was incorrect.
	 */
	public final static short SW_AUTH_FAILED = (short) 0x9C02;
	
	/**
	 * The card is locked, because the pin has been entered wrong to many times.
	 */
	public final static short SW_CARD_LOCKED = (short) 0x9C04;

	/**
	 * For the setup function - should only be called once 
	 */
	private boolean setupDone = false;
	
	/**
	 * OwnerPIN object. Used to authorize the user.
	 */
	private OwnerPIN pin;
	
	/**
	 * Constructor. Should initialize needed memory to prevent out of memory
	 * during runtime. Only this class's install method should create the applet
	 * object.
	 */
	private SecureBitcoinWalletJavaCardApplet() {
		pin = new OwnerPIN(PIN_RETRIES, PIN_MAXIMUM_SIZE);
		pin.update(DEFAULT_PIN, (byte) 0, (byte) DEFAULT_PIN.length);
		
		register();
	}

	/**
	 * Installs this applet.
	 *
	 * @param bArray
	 *            the array containing installation parameters
	 * @param bOffset
	 *            the starting offset in bArray
	 * @param bLength
	 *            the length in bytes of the parameter data in bArray
	 */
	public static void install(byte bArray[], short bOffset, byte bLength)
            throws ISOException {
		new SecureBitcoinWalletJavaCardApplet();
	}

	/**
	 * Processes APDU commands from the host.
	 * @param apdu The APDU command to process.
	 */
	@Override
	public void process(APDU apdu) throws ISOException {
		byte[] buffer = apdu.getBuffer();
        
        if ( selectingApplet() ) {
            return;
        }
   
        // Verify the CLA byte
        if (buffer[ ISO7816.OFFSET_CLA] != SECURE_BITCOIN_WALLET_CLA) {
        	ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
		
		// Check the INS byte
		switch (buffer[ ISO7816.OFFSET_INS]) {
		case INS_SETUP:
			setup(apdu, buffer);
			break;
		case INS_AUTHENTICATE:
			authenticate(apdu, buffer);
			break;
		case INS_CHANGE_PIN:
			changePin(apdu, buffer);
			break;
		case INS_PIN_VALIDATED:
			isPinValidated(apdu, buffer);
			break;
		default:				
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

	/**
	 * Setup of the card. Returns the PUK to reset the PIN. 
	 */
	private void setup(APDU apdu, byte[] buffer) {
		if (setupDone) {
			ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
		}
		setupDone = true;
	}

	/**
	 * Authenticates the user via the pin.
	 * 
	 * INS:		0x04
	 * P1:		0x00
	 * P2:		0x00
	 * Lc:		PIN length in bytes
	 * Data:	PIN itself
	 * 
	 * Return:	TODO
	 */
	private void authenticate(APDU apdu, byte[] buffer) {
		pin.reset();
		
		if (buffer[ISO7816.OFFSET_P1] != 0x00 || buffer[ISO7816.OFFSET_P1] != 0x00) {
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		}
		
		if (pin.getTriesRemaining() == (byte) 0x00) {
			ISOException.throwIt(SW_CARD_LOCKED);
		}

		if (apdu.setIncomingAndReceive() == 0) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		
		if (!pin.check(buffer, ISO7816.OFFSET_CDATA, buffer[ISO7816.OFFSET_LC])) {
			ISOException.throwIt(SW_AUTH_FAILED);
		}
	}
	
	/**
	 * Updates the PIN. The User has to be authenticated.
	 */
	private void changePin(APDU apdu, byte[] buffer) {
		if (!pin.isValidated()) {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}
		
		short avail = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		
		if (apdu.setIncomingAndReceive() != avail) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		
		if (avail < 4) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		
		byte pin_size = buffer[ISO7816.OFFSET_CDATA];
		
		if (avail < (short) (pin_size + 1)) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		
		pin.update(buffer, (short) (ISO7816.OFFSET_CDATA + 1), pin_size);
		pin.reset();
	}
	
	private void isPinValidated(APDU apdu, byte[] buffer) {
		buffer[0] = pin.isValidated() ? (byte) 1 : (byte) 0;
		
		apdu.setOutgoingAndSend((short) 0, (short) 1);
	}
}
