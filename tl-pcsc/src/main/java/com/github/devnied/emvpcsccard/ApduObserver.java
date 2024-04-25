package com.github.devnied.emvpcsccard;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
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

class EmvTagEntry implements Comparable<EmvTagEntry> {
    String tagHex = null;
    String setIn = null;
    String valueHex = null;

    String toXmlFragment(String indentString) {
        StringBuffer xmlFragment = new StringBuffer();
        xmlFragment.append(String.format(
            "%s<emv_tag_entry tag=\"%s\" set_in=\"%s\">\n",
            indentString, tagHex, setIn
        ));
        xmlFragment.append(indentString + indentString + valueHex + "\n");
        xmlFragment.append(indentString + "</emv_tag_entry>\n");
        return xmlFragment.toString();
    }

    public int compareTo(EmvTagEntry other) {
        int compareResult = tagHex.compareTo(other.tagHex);
        if(compareResult == 0) {
            compareResult = setIn.compareTo(other.setIn);
        }
        if(compareResult == 0) {
            // Not really a meaningful sorting key, but included
            // to make sorting fully deterministic on the 
            // value of the item.
            compareResult = valueHex.compareTo(other.valueHex);
        }
        return compareResult;
    }
}

public class ApduObserver {
	private static final Logger LOGGER = LoggerFactory.getLogger(ApduObserver.class);

    ArrayList<CommandAndResponse> m_commandsAndResponses = new ArrayList<CommandAndResponse>();
    TreeSet<EmvTagEntry> m_emvTagEntries = new TreeSet<EmvTagEntry>();

    // The medium (card, phone, watch, ring ...) can contain multiple applications
    // with different AIDs, and different EMV tags may be present or common EMV 
    // tags may have different values according to which AID is processed.
    // The following member attempts to track which AID is presently being considered
    // so that tag value differences can be examined.
    String m_currentAid = null;

    public ApduObserver() { }

    public void clearCurrentAid() {
        m_currentAid = null;
    }

    public void extractTags(CommandAndResponse carItem) {
        final int lengthOfExtraCommandBytes = Byte.toUnsignedInt(carItem.rawCommand[4]);
        final byte[] commandTlvBytes = Arrays.copyOfRange(
            carItem.rawCommand,5,5+lengthOfExtraCommandBytes
        );
        extractTags(
            commandTlvBytes, 
            String.format("step %2d terminal command",carItem.stepNumber)
        );

        final byte[] responseTlvBytes = Arrays.copyOfRange(
            carItem.rawResponse,0,carItem.rawResponse.length-2
        );
        extractTags(
            responseTlvBytes, 
            String.format("step %2d media response",carItem.stepNumber)
        );
    }

    void extractTags(byte[] tlvBytes, String setIn) {
		TLVInputStream stream = new TLVInputStream(new ByteArrayInputStream(tlvBytes));

		try {
			while (stream.available() > 0) {
				TLV tlv = TlvUtil.getNextTLV(stream);

				if (tlv == null) {
					LOGGER.warn("TLV format error");
					break;
				} else if(tlv.getTag().isConstructed()) {
                    extractTags(tlv.getValueBytes(),setIn);
                } else {
                    EmvTagEntry newEmvTagEntry = new EmvTagEntry();

                    newEmvTagEntry.tagHex = BytesUtils.bytesToStringNoSpace(tlv.getTagBytes());
                    newEmvTagEntry.valueHex = BytesUtils.bytesToString(tlv.getValueBytes());
                    newEmvTagEntry.setIn = setIn;
                    m_emvTagEntries.add(newEmvTagEntry);
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
                        clearCurrentAid(); // redundant, but included for clarity
                    } else if(Arrays.equals(extraBytes,"1PAY.SYS.DDF01".getBytes())) {
                        commandInterpretation.append("SELECT CONTACT PPE");
                        clearCurrentAid(); // redundant, but included for clarity
                    } else {
                        commandInterpretation.append("SELECT APPLICATION BY AID ");
                        m_currentAid = BytesUtils.bytesToStringNoSpace(extraBytes);
                        commandInterpretation.append(m_currentAid);
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
                cr.stepName = "GET_PROCESSING_OPTIONS for " + m_currentAid;
                commandInterpretation.append(cr.stepName + "\n");
                commandInterpretation.append(prettyPrintCommandExtraData(extraBytes));
                cr.interpretedCommand = commandInterpretation.toString();
            }
            break;

            case 0x80CA: {
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

    public String toXmlString() {
        final String indentString = "    ";
        StringBuffer xmlBuffer = new StringBuffer();
        xmlBuffer.append("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
        xmlBuffer.append("<emv_medium>\n");
        for(CommandAndResponse carItem: m_commandsAndResponses) {
            xmlBuffer.append(carItem.toXmlFragment(indentString));
        }
        xmlBuffer.append("</emv_medium>\n");

        xmlBuffer.append("<emv_tag_entry>\n");
        for(EmvTagEntry eteItem: m_emvTagEntries) {
            xmlBuffer.append(eteItem.toXmlFragment(indentString));
        }
        xmlBuffer.append("</emv_tag_entry\n");

        return xmlBuffer.toString();
    }

}
