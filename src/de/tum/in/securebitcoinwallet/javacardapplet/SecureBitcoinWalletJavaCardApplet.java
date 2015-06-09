package de.tum.in.securebitcoinwallet.javacardapplet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISOException;

/**
 * @author Benedikt Schlagberger
 *
 */
public class SecureBitcoinWalletJavaCardApplet extends Applet {

	/**
	 * Constructor. Should initialize needed memory to prevent out of memory during runtime.
	 */
	private SecureBitcoinWalletJavaCardApplet() {
		
	}

	/**
	 * Installs the applet on the card.
	 */
	public static void install(byte bArray[], short bOffset, byte bLength)
			throws ISOException {
		new SecureBitcoinWalletJavaCardApplet().register();
	}

	/**
	 * Processes APDU commands from the host.
	 */
	public void process(APDU arg0) throws ISOException {
		// TODO Auto-generated method stub

	}

}
