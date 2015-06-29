package de.tum.in.securebitcoinwallet.javacardapplet.test;

import static org.junit.Assert.assertEquals;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.Util;

import org.bouncycastle.util.encoders.Hex;

import com.licel.jcardsim.base.Simulator;

import de.tum.in.securebitcoinwallet.javacardapplet.SecureBitcoinWalletJavaCardApplet;

/**
 * Base class for Java Card applet tests.
 * 
 * @author Benedikt Schlagberger
 */
public abstract class AppletTestBase {

	/**
	 * The AID of the Secure Bitcoin Wallet Applet.
	 */
	protected static final String AID = "01020304050607080900";
	/**
	 * Simulator used for testing.
	 */
	public final Simulator simulator = new Simulator();

	/**
	 * Constructor. Initializes the simulator and selects the applet.
	 */
	public AppletTestBase() {
		byte[] aidBytes = Hex.decode(AID);
		AID aid = new AID(aidBytes, (short) 0, (byte) aidBytes.length);
		simulator.installApplet(aid, SecureBitcoinWalletJavaCardApplet.class);
		simulator.selectApplet(aid);
	}

	/**
	 * Checks whether the given response contains the ISO7816 response for success (0x9000).
	 * 
	 * @param response The response returned by the transmitted APDU command.
	 */
	protected void assertCommandSuccessful(byte[] response) {
		short statusCode = Util.getShort(response, (short) (response.length - 2));
		assertEquals(ISO7816.SW_NO_ERROR, statusCode);
	}

}