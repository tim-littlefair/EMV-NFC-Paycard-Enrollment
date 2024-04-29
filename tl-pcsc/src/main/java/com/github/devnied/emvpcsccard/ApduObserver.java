package com.github.devnied.emvpcsccard;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.TreeMap;
import java.util.TreeSet;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.devnied.emvnfccard.enums.SwEnum;
import com.github.devnied.emvnfccard.parser.IProvider;
import com.github.devnied.emvnfccard.utils.TlvUtil;
import com.github.devnied.emvnfccard.exception.CommunicationException;
import com.github.devnied.emvnfccard.exception.TlvException;
import com.github.devnied.emvnfccard.iso7816emv.TLV;

import fr.devnied.bitlib.BytesUtils;
import net.sf.scuba.tlv.TLVInputStream;

/**
 * Normal processing of an EMV payment media consists of 
 * exchange between the terminal and the media of a sequence of 
 * commands (from the terminal) and responses (from the media).
 * The following class contains raw and interpreted data about
 * a single command/response pair.
 */
class CommandAndResponse {
    int stepNumber = 0;
    String stepName = null;
    byte[] rawCommand = null;
    byte[] rawResponse = null;
    String interpretedCommand = null;
    String interpretedResponseStatus = null;
    String interpretedResponseBody = null;

    private void appendIndentedHexNode(
        StringBuffer fragmentBuffer, String nodeKey, String hexValueString, 
        int indentDepth, String indentString
    ) {
        for(int i=0; i<indentDepth;++i) {
            fragmentBuffer.append(indentString);
        }
        fragmentBuffer.append(String.format("<%s>\n",nodeKey));

        for(int i=0; i<indentDepth+1;++i) {
            fragmentBuffer.append(indentString);
        }
        fragmentBuffer.append(hexValueString);
        fragmentBuffer.append("\n");

        for(int i=0; i<indentDepth;++i) {
            fragmentBuffer.append(indentString);
        }
        fragmentBuffer.append(String.format("</%s>\n",nodeKey));
    }

    String toXmlFragment(String indentString) {
        StringBuffer xmlFragment = new StringBuffer();

        xmlFragment.append(String.format(
            "%s<command_and_response step_number=\"%d\" step_name=\"%s\">\n",
            indentString, stepNumber, stepName
        ));

        if(rawCommand!=null) {
            appendIndentedHexNode(
                xmlFragment, "raw_command", 
                BytesUtils.bytesToString(rawCommand),2,indentString
            );
        }
        if(interpretedCommand!=null) {
            xmlFragment.append(String.format(
                "%s<interpreted_command>\n%s\n%s</interpreted_command>\n",
                indentString + indentString,
                interpretedCommand.strip(),
                indentString + indentString
            ));
        }
        if(rawResponse!=null) {
            xmlFragment.append(String.format(
                "%s<raw_response>\n%s\n%s</raw_response>\n",
                indentString + indentString, 
                BytesUtils.bytesToString(rawResponse),
                indentString + indentString
            ));
        }            
        if(interpretedResponseStatus!=null) {
            xmlFragment.append(String.format(
                "%s<interpreted_response_status>%s</interpreted_response_status>\n",
                indentString+indentString, interpretedResponseStatus
            ));
        }
        if(interpretedResponseBody!=null) {
            xmlFragment.append(String.format(
                "%s<interpreted_response_body>\n%s\n%s</interpreted_response_body>\n",
                indentString + indentString, 
                interpretedResponseBody.strip(), 
                indentString + indentString
            ));
        }
        xmlFragment.append(indentString + "</command_and_response>\n");

        return xmlFragment.toString();
    }
}

// The medium (card, phone, watch, ring ...) can contain multiple applications
// with different AIDs, and different EMV tags may be present or common EMV 
// tags may have different values according to which entry in the PPSE has
// been selected (NB multiple PPSE entries may contain the same AID, for 
// example, for applications which are capable of being processed by more than one 
// kernel).
// The following members attempt to track which PPSE AID entry is presently being considered
// so that tag value differences between different selects.
class AppSelectionContext implements Comparable<AppSelectionContext> {
    final String aid;               // mandatory on creation
    String priority = "";           // optional - will be treated as highest priority if not found
    String appVersionNumber = null; // optional
    String appKernelId = null;      // optional
    String pdol = null;             // optional - used to interpret terminal tags attached to GPO command

    AppSelectionContext(String aid) {
        this.aid = aid;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(aid);
        if(appVersionNumber!=null) {
            sb.append("v" + appVersionNumber);
        }
        if(appKernelId!=null) {
            sb.append("k" + appKernelId);
        }
        if(priority.length()>0) {
            sb.append("p" + priority);
        }
        return sb.toString();
    }

    public int compareTo(AppSelectionContext other) {
        // In theory, within a single PPSE, priority should be
        // unique, so it should not be necessary to sort on 
        // anything else.
        return priority.compareTo(other.priority);
    }
}

/**
 * EMV tags can be sent in both commands and responses.
 * Note that nearly all EMV tags are sent and received during
 * the processing of a specific application - if the card contains
 * multiple applications there is no guarantee that a given tag
 * contains the same value in the context of one AID that it does
 * in the context of another or even that the same tags are 
 * defined in every context.
 * In practice, for most tags, we expect that they will have the
 * same value for all AIDs if defined, but it will be common for
 * some tags to be defined for some AIDs but not for others, but
 * the 'setIn' member of this class will enable traceability of 
 * tag values set during the command/response exchange to the AID 
 * which the value is associated with.
 */
class EmvTagEntry implements Comparable<EmvTagEntry> {
    String tagHex = null;
    String setBy = null;
    String setIn = null;
    String valueHex = null;

    String toXmlFragment(String indentString) {
        StringBuffer xmlFragment = new StringBuffer();
        xmlFragment.append(String.format(
            "%s<emv_tag_entry tag=\"%s\" set_by=\"%s\" set_in=\"%s\">\n",
            indentString, tagHex, setBy, setIn
        ));
        xmlFragment.append(indentString + indentString + valueHex + "\n");
        xmlFragment.append(indentString + "</emv_tag_entry>\n");
        return xmlFragment.toString();
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("[EMVTagEntry: tag=" + tagHex);
        if(setBy != null) {
            sb.append(" set_by=" + setBy);
        }
        if(setIn != null) {
            sb.append(" set_in=" + setIn);
        }
        sb.append(
            " value=" + 
            valueHex.replace(" ","") + 
            "]"
        );
        return sb.toString();
    }

    public int compareTo(EmvTagEntry other) {
        int compareResult = tagHex.compareTo(other.tagHex);
        if(compareResult == 0) {
            compareResult = setIn.compareTo(other.setIn);
        }
        /* 
        if(compareResult == 0) {
            compareResult = setBy.compareTo(other.setBy);
        }
        if(compareResult == 0) {
            // Not really a meaningful sorting key, but included
            // to make sorting fully deterministic on the 
            // value of the item.
            compareResult = valueHex.compareTo(other.valueHex);
        }
        */
        return compareResult;
    }
}

/**
 * The medium is typically identified by a three part tuple 
 * containing mandatory PAN, mandatory expiry month, and 
 * optional PAN sequence number (PSN)
 * All of these are from EMV tags which are received in responses
 * after a specific AID is selected, so in theory it would be possible
 * for different applications on the card to respond with different
 * values and the ApduObserver stores these in a 
 */
class AppAccountIdentifier implements Comparable<AppAccountIdentifier> {
    String applicationPAN = null;
    String applicationExpiryMonth = null;
    // If the PSN is not explicitly set we implicitly set it to 
    // the empty string (as null would not be comparable)
    String applicationPSN = "";

    public String toString() {
        if(applicationPSN.length()>0) {
            return String.format("%s.%s.%s",applicationPAN, applicationExpiryMonth,applicationPSN);
        } else {
            return String.format("%s.%s",applicationPAN, applicationExpiryMonth);
        }
    }

    public int compareTo(AppAccountIdentifier other) {
        int compareResult = applicationPAN.compareTo(other.applicationPAN);
        if(compareResult == 0) {
            compareResult = applicationPSN.compareTo(other.applicationPSN);
        }
        if(compareResult == 0) {
            compareResult = applicationExpiryMonth.compareTo(other.applicationExpiryMonth);
        }
        return compareResult;        
    }
}


public class ApduObserver {
	private static final Logger LOGGER = LoggerFactory.getLogger(ApduObserver.class);

    ArrayList<CommandAndResponse> m_commandsAndResponses = new ArrayList<CommandAndResponse>();
    TreeSet<EmvTagEntry> m_emvTagEntries = new TreeSet<EmvTagEntry>();
    TreeMap<AppSelectionContext,AppAccountIdentifier> m_accountIdentifiers = new TreeMap<AppSelectionContext,AppAccountIdentifier>();

    AppSelectionContext m_currentAppSelectionContext = null;
    AppAccountIdentifier m_currentAppAccountIdentifier = null;
    int m_mediumTransactionCounterNow = -1;
    int mediumTransactionCounterLastOnline = -1;

    boolean m_pciMaskingDone = false;

    public ApduObserver() { }

    public void openAppSelectionContext(String aid) {
        if(m_currentAppSelectionContext == null) {
            m_currentAppSelectionContext = new AppSelectionContext(aid);
            m_currentAppAccountIdentifier = new AppAccountIdentifier();
        } else if(!m_currentAppSelectionContext.aid.equals(aid)) {
            closeAppSelectionContext();
            m_currentAppSelectionContext = new AppSelectionContext(aid);
            m_currentAppAccountIdentifier = new AppAccountIdentifier();
        }
    }

    public void closeAppSelectionContext() {
        if(m_currentAppSelectionContext == null) {
            return;
        }
        if(m_accountIdentifiers.containsKey(m_currentAppSelectionContext)) {
            LOGGER.warn(
                "PPSE contains multiple records at priority " + 
                m_currentAppSelectionContext.priority
            );
            LOGGER.warn(String.format(
                "The PPSE record for selection context %s will not be captured", 
                m_currentAppSelectionContext.toString()
            ));
        } else {
            LOGGER.info(String.format(
                "App account identifier for selection context %s is %s",
                m_currentAppSelectionContext,
                m_currentAppAccountIdentifier
            ));
            m_accountIdentifiers.put(
                m_currentAppSelectionContext,
                m_currentAppAccountIdentifier
            );
        }
        m_currentAppAccountIdentifier = null;
        m_currentAppSelectionContext = null;
    }

    public void extractTags(CommandAndResponse carItem) {
        final int lengthOfExtraCommandBytes = Byte.toUnsignedInt(carItem.rawCommand[4]);
        final byte[] commandTlvBytes = Arrays.copyOfRange(
            carItem.rawCommand,5,5+lengthOfExtraCommandBytes
        );
        extractTags(commandTlvBytes, carItem);

        final byte[] responseTlvBytes = Arrays.copyOfRange(
            carItem.rawResponse,0,carItem.rawResponse.length-2
        );
        extractTags(responseTlvBytes, carItem);
    }

    void extractTags(byte[] tlvBytes, CommandAndResponse carItem) {
		TLVInputStream stream = new TLVInputStream(new ByteArrayInputStream(tlvBytes));
        ArrayList<EmvTagEntry> newTagList = new ArrayList<EmvTagEntry>();
        extractTagsRecursively(stream, newTagList);
        for(EmvTagEntry ete: newTagList) {
            // We defer setting ete.setIn until here so that m_currentAid
            // reflects all attributes of the selected AID entry
            // (NB the same AID may be selected more than once at 
            // different priorities)
            if(m_currentAppSelectionContext != null) {
                ete.setIn = m_currentAppSelectionContext.toString();
            } else {
                ete.setIn = "<none>";
            }
            LOGGER.info(ete.toString());
            m_emvTagEntries.add(ete);
        }
    }

    void extractTagsRecursively(TLVInputStream stream, ArrayList<EmvTagEntry> newTagList) {
        try {
			while (stream.available() > 0) {
				TLV tlv = TlvUtil.getNextTLV(stream);

				if (tlv == null) {
					LOGGER.warn("TLV format error");
					break;
				} else if(tlv.getTag().isConstructed()) {
                    TLVInputStream stream2 = new TLVInputStream(new ByteArrayInputStream(tlv.getValueBytes()));
                    extractTagsRecursively(stream2,newTagList);
                } else {
                    EmvTagEntry newEmvTagEntry = new EmvTagEntry();
                    newEmvTagEntry.tagHex = BytesUtils.bytesToStringNoSpace(tlv.getTagBytes());
                    newEmvTagEntry.valueHex = BytesUtils.bytesToString(tlv.getValueBytes());
                    reflectTagInSelectionContextAndAccountIdentifier(newEmvTagEntry.tagHex,newEmvTagEntry.valueHex);
                    newTagList.add(newEmvTagEntry);
                }
            }
        } catch (IOException e) {
            LOGGER.error(e.getMessage(), e);
        } catch (TlvException exce) {
            LOGGER.warn(exce.getMessage(), exce);
        } 

        try {
            stream.close();
        }
        catch(IOException e) {
            LOGGER.warn("IOException caught and ignored while closing TLV stream");
        }
    }

    void reflectTagInSelectionContextAndAccountIdentifier(String tagHex, String tagValueHex) {
        tagValueHex = tagValueHex.replaceAll(" ","");
        if(tagHex.equals("4F")) {
            openAppSelectionContext(tagValueHex.replaceAll(" ",""));
        } else if(tagHex.equals("87")) {
            m_currentAppSelectionContext.priority = tagValueHex;
        } else if(tagHex.equals("9F2A")) {
            m_currentAppSelectionContext.appKernelId = tagValueHex;
        } else if(tagHex.equals("????")) {
            m_currentAppSelectionContext.appVersionNumber = tagValueHex;
        } else if(tagHex.equals("57")) {
            // track 2 equivalent data
            int separatorPos = tagValueHex.indexOf("D");
            if(separatorPos > 0) {
                m_currentAppAccountIdentifier.applicationPAN = tagValueHex.substring(0,separatorPos);
                m_currentAppAccountIdentifier.applicationExpiryMonth = tagValueHex.substring(separatorPos+1, separatorPos+5);
            } else {
                LOGGER.warn("Invalid track 2 equivalent ignored");
                return;
            }
        } else if(tagHex.equals("5F34")) {
            m_currentAppAccountIdentifier.applicationPSN = tagValueHex;
        } else if(tagHex.equals("9F36")) {
            byte[] atcBytes = BytesUtils.fromString(tagValueHex);
            m_mediumTransactionCounterNow = (0xFF&atcBytes[0]*0x100) + (0xFF&atcBytes[1]); 
        } else if(tagHex.equals("9F17")) {
            byte[] lotcBytes = BytesUtils.fromString(tagValueHex);
            mediumTransactionCounterLastOnline =  (0xFF&lotcBytes[0]*0x100) + (0xFF&lotcBytes[1]); 
        }
}

    void interpretCommand(CommandAndResponse cr) {
        int cla_ins = BytesUtils.byteArrayToInt(cr.rawCommand,0,2);
        int p1_p2 = BytesUtils.byteArrayToInt(cr.rawCommand,2,2);
        StringBuffer commandInterpretation = new StringBuffer();

        switch(cla_ins) {
            case 0x00a4: {
                int lengthOfExtraBytes = cr.rawCommand[4];
                byte[] extraBytes = Arrays.copyOfRange(cr.rawCommand,5,5+lengthOfExtraBytes);
                if(p1_p2 == 0x0400) {
                    if(Arrays.equals(extraBytes,"2PAY.SYS.DDF01".getBytes())) {
                        commandInterpretation.append("SELECT CONTACTLESS PPSE");
                    } else if(Arrays.equals(extraBytes,"1PAY.SYS.DDF01".getBytes())) {
                        commandInterpretation.append("SELECT CONTACT PPE");
                    } else {
                        commandInterpretation.append("SELECT APPLICATION BY AID ");
                        String aid = BytesUtils.bytesToStringNoSpace(extraBytes);
                        commandInterpretation.append(aid);
                    }
                    cr.interpretedCommand = commandInterpretation.toString();
                } else {
                    // Don't expect this but ISO 7816 does define other modes of select
                    // selected via p1_p2 so interpret in case we ever see them used.
                    commandInterpretation.append("SELECT_BY_???? ");
                    commandInterpretation.append(
                        String.format("p1_p2=%04x extra_bytes=%s", 
                        p1_p2, BytesUtils.bytesToString(extraBytes)
                    ));
                    cr.interpretedCommand = commandInterpretation.toString();
                }
            }
            break;

            case 0x80A8: {
                int lengthOfExtraBytes = cr.rawCommand[4];
                byte[] extraBytes = Arrays.copyOfRange(cr.rawCommand,5,5+lengthOfExtraBytes);
                cr.stepName = "GET_PROCESSING_OPTIONS for most recent selected AID";
                commandInterpretation.append(cr.stepName + "\n");
                commandInterpretation.append(prettyPrintCommandExtraData(extraBytes));
                cr.interpretedCommand = commandInterpretation.toString();
            }
            break;

            case 0x80CA: {
                // Tags accessed via GET DATA belong to the medium, not a specific
                // application, so close off the app selection context if it is open.
                // exists, close it off.
                closeAppSelectionContext();

                String tagHex = String.format("%X",p1_p2);
                commandInterpretation.append("GET_DATA for tag " + tagHex);
                cr.interpretedCommand = commandInterpretation.toString();
            }
            break;

            case 0x00B2: {
                commandInterpretation.append("READ_RECORD");
                cr.interpretedCommand = commandInterpretation.toString();
            }
            break;

            default:
                cr.interpretedCommand = String.format("Unexpected CLA/INS %04x", cla_ins);
        }
        // Some commands will have multi-line interpretations - for these, carName 
        // should have been set to a single-line string before the first 
        // carriage return was inserted.
        // Otherwise, hopefully commandInterpretation contains a single line string
        // which we can use as the name of the command/response pair. 
        if(cr.stepName == null) {
            cr.stepName = commandInterpretation.toString();
        }
    }

    String prettyPrintCommandExtraData(byte[] commandExtraBytes) {
        // The GPO command sends some EMV tags related to the terminal
        // configuration, this function is provided to pretty-print 
        // these.
        // We hijack the behaviour of devied's prettyPrintAPDUResponse for
        // this.  Responses are expected to end with a two-byte status 
        // word, so we fake one up.
        byte[] fakeResponseBuffer = new byte[commandExtraBytes.length + 2];
        System.arraycopy(commandExtraBytes,0,fakeResponseBuffer,0,commandExtraBytes.length);
        fakeResponseBuffer[commandExtraBytes.length] = (byte) 0x90;
        fakeResponseBuffer[commandExtraBytes.length + 1] = (byte) 0x00;

        String prettyApdu = TlvUtil.prettyPrintAPDUResponse(fakeResponseBuffer);
        prettyApdu = prettyApdu.strip();
        int lastCarriageReturnPosition = prettyApdu.lastIndexOf("\n");

        return prettyApdu.substring(0,lastCarriageReturnPosition);
    }

    void interpretResponse(CommandAndResponse cr) {
        if(cr.interpretedResponseStatus != null) {
            // If this is already filled in it describes an exception,
            // there is nothing more to be done
            return;
        }
        SwEnum swval = SwEnum.getSW(cr.rawResponse);
        if (swval != null) {
            cr.interpretedResponseStatus = swval.toString();
            String prettyApdu = TlvUtil.prettyPrintAPDUResponse(cr.rawResponse);

            // remove the status word as we already have it.
            prettyApdu = prettyApdu.strip();
            int lastCarriageReturnPosition = prettyApdu.lastIndexOf("\n");
            if(lastCarriageReturnPosition > 0) {
                prettyApdu = prettyApdu.substring(0,lastCarriageReturnPosition);
            }
    		cr.interpretedResponseBody = prettyApdu;
        } else {
            cr.interpretedResponseStatus = "Status word not found";
            cr.interpretedResponseBody = "Not parsed";
        }
    }

    public void add(CommandAndResponse newCommandAndResponse) {
        newCommandAndResponse.stepNumber = m_commandsAndResponses.size() + 1;
        m_commandsAndResponses.add(newCommandAndResponse);
    }

    public void pciMaskAccountData() {
        // The following map will contain pairs of Strings, where
        // the key is a sensitive value which requires masking, 
        // and the associated value is the masked value
        TreeMap<String,String> maskPairs = new TreeMap<>();

        for(AppAccountIdentifier appAccountId: m_accountIdentifiers.values()) {

            String panWithoutSpaces = appAccountId.applicationPAN;
            char[] maskingChars = new char[panWithoutSpaces.length()-10];
            Arrays.fill(maskingChars,'F');
            String maskingString = new String(maskingChars);
            String maskedPanWithoutSpaces = String.format(
                "%s%s%s",panWithoutSpaces.substring(0,6),
                maskingString,
                panWithoutSpaces.substring(panWithoutSpaces.length()-4)
            );
            maskPairs.put(panWithoutSpaces, maskedPanWithoutSpaces);


            ArrayList<CommandAndResponse> scrubbedCommandsAndResponses = new ArrayList<>();
            for(CommandAndResponse carItem: m_commandsAndResponses) {
                for(String sensitiveString: maskPairs.keySet()) {
                    String maskedString = maskPairs.get(sensitiveString);

                    carItem.rawResponse = BytesUtils.fromString(
                        BytesUtils.bytesToStringNoSpace(
                            carItem.rawResponse
                        ).replaceAll(sensitiveString,maskedString)
                    );

                    String sensitiveStringWithSpaces = hexReinsertSpacesBetweenBytes(sensitiveString);
                    String maskedStringWithSpaces = hexReinsertSpacesBetweenBytes(maskedString);
                    carItem.interpretedResponseBody = 
                        carItem.interpretedResponseBody.replaceAll(sensitiveStringWithSpaces,maskedStringWithSpaces);
                }
                scrubbedCommandsAndResponses.add(carItem);
            }
            m_commandsAndResponses = scrubbedCommandsAndResponses;
        }
        m_pciMaskingDone = true;
    }

    private String hexReinsertSpacesBetweenBytes(String hexWithoutSpaces) {
        StringBuilder hexWithSpacesSB = new StringBuilder();
        while(true) {
            hexWithSpacesSB.append(hexWithoutSpaces.substring(0,2));
            hexWithoutSpaces = hexWithoutSpaces.substring(2);
            if(hexWithoutSpaces.length()>0) {
                hexWithSpacesSB.append(" ");
            } else {
                break;
            } 
        }
        return hexWithSpacesSB.toString();
    }

    public String toXmlString() {
        final String indentString = "    ";
        StringBuffer xmlBuffer = new StringBuffer();

        xmlBuffer.append("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
        xmlBuffer.append("<emv_medium>\n");

        if(m_pciMaskingDone != true) {
            xmlBuffer.append(
                indentString + 
                "<!-- PCI masking not done yet - no data can be returned -->\n"
            );
        } else {
            for(CommandAndResponse carItem: m_commandsAndResponses) {
                xmlBuffer.append(carItem.toXmlFragment(indentString));
            }            

            for(EmvTagEntry eteItem: m_emvTagEntries) {
                xmlBuffer.append(eteItem.toXmlFragment(indentString));
            }

            for(AppSelectionContext asc: m_accountIdentifiers.keySet()) {
                xmlBuffer.append(String.format(
                    "%s<app_account_id selection_context=\"%s\" account_id=\"%s\" />\n",
                    indentString, asc, m_accountIdentifiers.get(asc)
                ));
            }
        }

        xmlBuffer.append("</emv_medium>\n");

        return xmlBuffer.toString();
    }

    public String mediumStateId() {
        String primaryAppIdentifier = "none_found";
        for(AppAccountIdentifier appAccId: m_accountIdentifiers.values()) {
            primaryAppIdentifier = appAccId.toString();
            break;
        }
        return String.format(
            "%s@atc=%04d",
            primaryAppIdentifier,m_mediumTransactionCounterNow
        );
    }
}
