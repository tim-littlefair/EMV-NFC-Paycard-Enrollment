package com.github.devnied.emvpcsccard;

import java.nio.ByteBuffer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.devnied.emvnfccard.enums.SwEnum;
import com.github.devnied.emvnfccard.parser.IProvider;
import com.github.devnied.emvnfccard.utils.TlvUtil;
import com.github.devnied.emvnfccard.exception.CommunicationException;

import fr.devnied.bitlib.BytesUtils;

public abstract class MyProviderBase implements IProvider {

	/**
	 * Class logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(MyProviderBase.class);    

	/**
	 * Buffer
	 */
	private final ByteBuffer buffer = ByteBuffer.allocate(1024);

    protected abstract byte[] implementationTransceive(final byte[] pCommand, ByteBuffer receiveBuffer) throws CommunicationException;

    @Override
	public byte[] transceive(final byte[] pCommand) throws CommunicationException {
		byte[] ret = null;
		buffer.clear();
		LOGGER.info("send: " + BytesUtils.bytesToString(pCommand));
		try {
            ret = implementationTransceive(pCommand, buffer);
		} catch (CommunicationException e) {
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

	abstract public byte[] getAt();    
}
