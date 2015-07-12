package de.tum.in.securebitcoinwallet.javacardapplet.test;

import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import javacard.framework.AID;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import com.licel.jcardsim.base.Simulator;

import de.tum.in.securebitcoinwallet.javacardapplet.AppletInstructions;
import de.tum.in.securebitcoinwallet.javacardapplet.SecureBitcoinWalletJavaCardApplet;
import de.tum.in.securebitcoinwallet.javacardapplet.test.tests.AppletTestBase;

public class JavaCardSimulator implements JavaCard {
	private Simulator simulator;

	public JavaCardSimulator(byte[] appletID) {
		simulator = new Simulator();
		AID aid = new AID(appletID, (short) 0, (byte) appletID.length);
		simulator.installApplet(aid, SecureBitcoinWalletJavaCardApplet.class);
		simulator.selectApplet(aid);
	}

	@Override
	public ResponseAPDU transmit(CommandAPDU command) {
		return new ResponseAPDU(simulator.transmitCommand(command.getBytes()));
	}

	@Override
	public byte[] setup() throws CardException {
		byte[] puk;

		CommandAPDU setupInstruction = new CommandAPDU(
				AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
				AppletInstructions.INS_SETUP, 0, 0);
		ResponseAPDU response = transmit(setupInstruction);

		assertTrue(AppletTestBase.commandSuccessful(response));

		puk = Arrays.copyOf(response.getBytes(),
				SecureBitcoinWalletJavaCardApplet.PUK_SIZE);
		
		return puk;
	}

}
