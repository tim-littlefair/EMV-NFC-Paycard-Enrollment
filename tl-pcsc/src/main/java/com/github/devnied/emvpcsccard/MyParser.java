package com.github.devnied.emvpcsccard;

import java.util.List;

import org.apache.commons.lang3.ArrayUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.devnied.emvnfccard.enums.SwEnum;
import com.github.devnied.emvnfccard.exception.CommunicationException;
import com.github.devnied.emvnfccard.iso7816emv.EmvTags;
import com.github.devnied.emvnfccard.model.Application;
import com.github.devnied.emvnfccard.model.EmvCard;
import com.github.devnied.emvnfccard.model.enums.ApplicationStepEnum;
import com.github.devnied.emvnfccard.model.enums.CardStateEnum;
import com.github.devnied.emvnfccard.parser.EmvTemplate;
import com.github.devnied.emvnfccard.parser.impl.EmvParser;
import com.github.devnied.emvnfccard.utils.ResponseUtils;
import com.github.devnied.emvnfccard.utils.TlvUtil;
import com.github.devnied.emvnfccard.model.Afl;
import com.github.devnied.emvnfccard.utils.CommandApdu;
import com.github.devnied.emvnfccard.enums.CommandEnum;


import fr.devnied.bitlib.BytesUtils;

class MyParser extends EmvParser {

	/**
	 * Class Logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(MyParser.class);

    /**
     * Default constructor
     *
     * @param pTemplate parser template
     */


    public MyParser(EmvTemplate pTemplate) {
        super(pTemplate);
    }

	/**
	 * This method overrides devnied's implementation in the superclass
     * to re-discover the application file locator bytes, and to read 
     * all of the files associated with the application (devnied's 
     * implementation only reads files until the track data is found)
	 *
	 * @param pGpo
	 *            global processing options response
	 * @return true if the extraction succeed
	 * @throws CommunicationException communication error
	 */
    @Override
	protected boolean extractCommonsCardData(final byte[] pGpo) throws CommunicationException {
        // Invoke devnied's implementation first to fill all of the fields required by 
        // his EmvCard class
        boolean retval =  super.extractCommonsCardData(pGpo);
        if(retval == true) {
            final byte[] aflBytes;
            final byte[] rmt1Bytes = TlvUtil.getValue(pGpo, EmvTags.RESPONSE_MESSAGE_TEMPLATE_1);
            if(rmt1Bytes != null) {
                aflBytes = ArrayUtils.subarray(rmt1Bytes, 2, rmt1Bytes.length);
            } else {
                aflBytes = TlvUtil.getValue(pGpo, EmvTags.APPLICATION_FILE_LOCATOR);
            }

            if(aflBytes != null) {
                List<Afl> listAfl = extractAfl(aflBytes);
                LOGGER.info(String.format("AFL list=" + BytesUtils.bytesToString(aflBytes)));
                // for each AFL
                for (Afl afl : listAfl) {
                    // check all records
                    for (int index = afl.getFirstRecord(); index <= afl.getLastRecord(); index++) {
                        LOGGER.debug(String.format("Attempting to read AFL[%d.%d]",afl.getSfi(),index,afl));
                        byte[] info = template.get().getProvider()
                                .transceive(new CommandApdu(CommandEnum.READ_RECORD, index, afl.getSfi() << 3 | 4, 0).toBytes());
                        // Extract card data
                        if (ResponseUtils.isSucceed(info)) {
                            LOGGER.info(String.format("AFL[%d.%d] bytes=%s",afl.getSfi(),index,BytesUtils.bytesToString(info)));
                            LOGGER.info("Tags:" + TlvUtil.prettyPrintAPDUResponse(info));
                        }
                    }
                }
            } else {
                LOGGER.error("AFL not found in GPO: " + BytesUtils.bytesToString(pGpo));
            }

        } else {
            LOGGER.error("EmvParser.extractCommonsCardData failed - not reading AFL data");
        }

        return retval;
    }
}

