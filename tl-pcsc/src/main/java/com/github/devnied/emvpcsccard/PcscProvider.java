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

	/*
	@Override
	public byte[] transceive(final byte[] pCommand) throws CommunicationException {
		byte[] ret = null;
		buffer.clear();
		LOGGER.info("send: " + BytesUtils.bytesToString(pCommand));
		try {
			int nbByte = channel.transmit(ByteBuffer.wrap(pCommand), buffer);
			ret = new byte[nbByte];
			System.arraycopy(buffer.array(), 0, ret, 0, ret.length);
		} catch (CardException e) {
			LOGGER.error("PcscProvider.tranceive: Exception during send: " + e.getMessage());
		}
		LOGGER.info("resp: " + BytesUtils.bytesToString(ret));
		try {
			String apduPrettyOutput = TlvUtil.prettyPrintAPDUResponse(ret);
			if(apduPrettyOutput != null && apduPrettyOutput.length()>0) {
				LOGGER.info(apduPrettyOutput);
			}
			SwEnum val = SwEnum.getSW(ret);
			if (val != null) {
				LOGGER.info("statusWord: " + val.getDetail());
			}
		} catch (Exception e) {
		LOGGER.error("PcscProvider.tranceive: Exception during receive: " + e.getMessage());
		}

		return ret;
	}
*/
	@Override
	public byte[] getAt() {
		return channel.getCard().getATR().getBytes();
	}

}
