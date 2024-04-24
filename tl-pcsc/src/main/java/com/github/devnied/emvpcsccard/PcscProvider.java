package com.github.devnied.emvpcsccard;

import java.nio.ByteBuffer;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.devnied.emvnfccard.enums.SwEnum;
import com.github.devnied.emvnfccard.exception.CommunicationException;
import com.github.devnied.emvnfccard.parser.IProvider;
import com.github.devnied.emvnfccard.utils.TlvUtil;


import fr.devnied.bitlib.BytesUtils;

public class PcscProvider extends MyProviderBase {

	/**
	 * CardChanel
	 */
	private final CardChannel channel;


	/**
	 * Constructor using field
	 *
	 * @param pChannel
	 *            card channel
	 */
	public PcscProvider(final CardChannel pChannel) {
		channel = pChannel;
	}

    protected byte[] implementationTransceive(final byte[] pCommand, ByteBuffer receiveBuffer) throws CommunicationException {
		try {
			int nbByte = channel.transmit(ByteBuffer.wrap(pCommand), receiveBuffer);
			byte[] ret = new byte[nbByte];
			System.arraycopy(receiveBuffer.array(), 0, ret, 0, ret.length);
			return ret;
		} catch(CardException e) {
			throw new CommunicationException(e.getMessage());
		}
	}

	@Override
	public byte[] getAt() {
		return channel.getCard().getATR().getBytes();
	}

}
