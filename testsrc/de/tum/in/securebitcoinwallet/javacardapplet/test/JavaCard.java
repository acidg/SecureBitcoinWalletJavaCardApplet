package de.tum.in.securebitcoinwallet.javacardapplet.test;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public interface JavaCard {	
	public ResponseAPDU transmit(CommandAPDU command) throws CardException;
	
	public byte[] setup() throws CardException;
}
