package net.heretical_camelid.transit_cemv_checker.library;

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
	private static final Logger LOGGER = LoggerFactory.getLogger(MyParser.class);

    private APDUObserver m_apduObserver = null;

    /**
     * Default constructor
     *
     * @param pTemplate parser template
     * @param apduObserver
     */
    public MyParser(EmvTemplate pTemplate, APDUObserver apduObserver) {
        super(pTemplate);
        m_apduObserver = apduObserver;
    }

	/**
	 * This method overrides devnied's implementation in the superclass
     * to re-discover the application file locator bytes, and to read 
     * all of the records associated with the application (devnied's 
     * implementation only reads records until the track data is found,
     * and usually leaves the records containing CAPK index and other
     * transit-relevant tags unread).
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
            final byte[] rmt2Bytes = TlvUtil.getValue(pGpo, EmvTags.RESPONSE_MESSAGE_TEMPLATE_2);
            if(rmt2Bytes != null) {
                aflBytes = ArrayUtils.subarray(rmt2Bytes, 2, rmt2Bytes.length);
            } else {
                aflBytes = TlvUtil.getValue(pGpo, EmvTags.APPLICATION_FILE_LOCATOR);                
            }
            
            if(aflBytes != null) {
                List<Afl> listAfl = extractAfl(aflBytes);
                // for each AFL
                for (Afl afl : listAfl) {
                    // check all records
                    for (int index = afl.getFirstRecord(); index <= afl.getLastRecord(); index++) {
                        LOGGER.debug(String.format("Attempting to read AFL[%d.%d]",afl.getSfi(),index,afl));
                        template.get().getProvider()
                            .transceive(
                                new CommandApdu(
                                    CommandEnum.READ_RECORD, 
                                    index, afl.getSfi() << 3 | 4, 0
                                ).toBytes()
                            );
                    }
                }
            } else {
                // The AFL seems to be optional - 
                // for some cards the GPO must return all tags required
                LOGGER.warn("AFL not found in GPO response: " + BytesUtils.bytesToString(pGpo));
            }

        } else {
            LOGGER.error("EmvParser.extractCommonsCardData failed - not reading AFL data");
        }
        m_apduObserver.closeAppSelectionContext();

        return retval;
    }
}

