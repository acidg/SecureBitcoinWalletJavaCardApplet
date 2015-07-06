package de.tum.in.securebitcoinwallet.javacardapplet.test;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;

import org.bouncycastle.util.encoders.Hex;

import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.Util;

import com.licel.jcardsim.base.Simulator;

import de.tum.in.securebitcoinwallet.javacardapplet.AppletInstructions;
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
	protected final Simulator simulator = new Simulator();

	protected final byte[] puk;

	/**
	 * Constructor. Initializes the simulator and selects the applet. Also calls
	 * the setup instruction and retrieves the PUK.
	 */
	public AppletTestBase() {
		byte[] aidBytes = Hex.decode(AID);
		AID aid = new AID(aidBytes, (short) 0, (byte) aidBytes.length);
		simulator.installApplet(aid, SecureBitcoinWalletJavaCardApplet.class);
		simulator.selectApplet(aid);

		byte[] setupInstruction = {
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_SETUP, 0x00, 0x00 };

		puk = Arrays.copyOf(simulator.transmitCommand(setupInstruction),
				SecureBitcoinWalletJavaCardApplet.PUK_SIZE);
		System.out.println();
	}

	/**
	 * Checks whether the given response contains the ISO7816 response for
	 * success (0x9000).
	 * 
	 * @param response The response returned by the transmitted APDU command.
	 */
	protected void assertCommandSuccessful(byte[] response) {
		short statusCode = Util.getShort(response,
				(short) (response.length - 2));
		assertEquals(ISO7816.SW_NO_ERROR, statusCode);
	}

}