package de.tum.in.securebitcoinwallet.javacardapplet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * For now, this class implements a hello world applet which just echos the
 * received commands.
 * 
 * @author Benedikt Schlagberger
 */
public class SecureBitcoinWalletJavaCardApplet extends Applet {
	private byte[] echoBytes;
	private static final short LENGTH_ECHO_BYTES = 256;

	/**
	 * Constructor. Should initialize needed memory to prevent out of memory
	 * during runtime. Only this class's install method should create the applet
	 * object.
	 */
	private SecureBitcoinWalletJavaCardApplet() {
		echoBytes = new byte[LENGTH_ECHO_BYTES];
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
		new SecureBitcoinWalletJavaCardApplet().register();
	}

	/**
	 * Processes APDU commands from the host.
	 * @param apdu The APDU command to process.
	 */
	public void process(APDU apdu) throws ISOException {
		byte buffer[] = apdu.getBuffer();

		if (selectingApplet()) {
			return;
		}

		short bytesRead = apdu.setIncomingAndReceive();
		short echoOffset = (short) 0;

		while (bytesRead > 0) {
			Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, echoBytes,
					echoOffset, bytesRead);
			echoOffset += bytesRead;
			bytesRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
		}

		apdu.setOutgoing();
		apdu.setOutgoingLength((short) (echoOffset + 5));

		// echo header
		apdu.sendBytes((short) 0, (short) 5);
		// echo data
		apdu.sendBytesLong(echoBytes, (short) 0, echoOffset);
	}

}
