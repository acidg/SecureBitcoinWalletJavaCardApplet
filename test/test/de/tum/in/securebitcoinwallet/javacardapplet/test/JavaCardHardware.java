package de.tum.in.securebitcoinwallet.javacardapplet.test;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.channels.Channel;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import de.tum.in.securebitcoinwallet.javacardapplet.AppletInstructions;
import de.tum.in.securebitcoinwallet.javacardapplet.SecureBitcoinWalletJavaCardApplet;
import de.tum.in.securebitcoinwallet.javacardapplet.test.tests.AppletTestBase;

public class JavaCardHardware implements JavaCard {
	
	private CardChannel smartCard;
	
	public JavaCardHardware(byte[] appletID) throws CardException {
		TerminalFactory factory = TerminalFactory.getDefault();

		CardTerminal terminal = factory.terminals().list().get(0);
		// establish a connection with the card
		Card card = null;
		card = terminal.connect("*");
		smartCard = card.getBasicChannel();

		selectAID(appletID);
	}
	
	@Override
	public ResponseAPDU transmit(CommandAPDU command) throws CardException {
		return smartCard.transmit(command);
	}

	@Override
	public byte[] setup() throws CardException {
		byte[] puk = new byte[SecureBitcoinWalletJavaCardApplet.PUK_SIZE];
		File pukFile = new File("bin/puk");
		if (pukFile.exists()) {
			try {
				puk = Files.readAllBytes(pukFile.toPath());
			} catch (IOException e) {
				// Ignore and try setup
			}
		} else {
			CommandAPDU setupInstruction = new CommandAPDU(
					AppletInstructions.SECURE_BITCOIN_WALLET_CLA,
					AppletInstructions.INS_SETUP, 0, 0);
			ResponseAPDU response = smartCard.transmit(setupInstruction);

			assertTrue(AppletTestBase.commandSuccessful(response));

			puk = Arrays.copyOf(response.getBytes(),
					SecureBitcoinWalletJavaCardApplet.PUK_SIZE);

			try {
				Files.write(pukFile.toPath(), puk, StandardOpenOption.CREATE);
			} catch (IOException e) {
				throw new RuntimeException("PUK file could not be created in "
						+ pukFile.getAbsolutePath() + "PUK: "
						+ AppletTestBase.getHexString(puk));
			}
		}
		return puk;
	}
	
	/**
	 * Sends the select aid APDU to the card.
	 * 
	 * @param aid The AID to select
	 * @throws CardException
	 */
	private void selectAID(byte[] aid) throws CardException {
		CommandAPDU selectAIDCommand = new CommandAPDU(0x00, 0xA4, 0x04, 0x00,
				aid);

		ResponseAPDU response = smartCard.transmit(selectAIDCommand);

		assertTrue(AppletTestBase.commandSuccessful(response));
	}

}
