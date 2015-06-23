package de.tum.in.securebitcoinwallet.javacardapplet;

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
	private final static byte PIN_RETRIES = 3;
	
	/**
	 * Maximum number of pin retries.
	 */
	private final static byte PIN_MAXIMUM_SIZE = 4;
	
	/**
	 * The preset default pin.
	 */
	private final static byte[] DEFAULT_PIN = { 1, 2, 3, 4 };
	
	/**
	 * CLA instruction class for Secure Bitcoin Wallet app instructions.
	 */
	private final static byte SECURE_BITCOIN_WALLET_CLA = (byte) 0xA0;
	
	/**
	 * Setup Instruction.
	 */
	private final static byte INS_SETUP = (byte) 0x01;
	
	/**
	 * Set pin instruction.
	 */
	private final static byte INS_SET_PIN = (byte) 0x02;
	
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
			setup();
			break;
		case INS_SET_PIN:
			setPin();
			break;
		default:				
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

	private void setPin() {
		// TODO Auto-generated method stub
		
	}

	private void setup() {
		// TODO Auto-generated method stub
		
	}
}
