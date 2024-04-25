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

        xmlFragment.append(String.format("    <command_and_response name=\"%s\">\n",stepName));

        if(rawCommand!=null) {
            appendIndentedHexNode(
                xmlFragment, "raw_command", 
                BytesUtils.bytesToString(rawCommand),2,indentString
            );
        }
        if(interpretedCommand!=null) {
            xmlFragment.append(String.format(
                "        <interpreted_command>\n%s\n" +
                "        </interpreted_command>\n",
                interpretedCommand
            ));
        }
        if(rawResponse!=null) {
            xmlFragment.append(String.format(
                "        <raw_response>%s</raw_response>\n",
                BytesUtils.bytesToString(rawResponse)
            ));
        }            
        if(interpretedResponseStatus!=null) {
            xmlFragment.append(String.format(
                "        <interpreted_response_status>%s</interpreted_response_status>\n",
                interpretedResponseStatus
            ));
        }
        if(interpretedCommand!=null) {
            xmlFragment.append(String.format(
                "        <interpreted_response_body>%s\n" +
                "        </interpreted_response_body>\n",
                interpretedResponseBody
            ));
        }
        xmlFragment.append("    </command_and_response>\n");

        return xmlFragment.toString();
    }
}

class EmvTagEntry implements Comparable<EmvTagEntry> {
    String tagHex = null;
    String aid = null;
    String setIn = null;
    String valueHex = null;

    String toXmlFragment(String indentString) {
        StringBuffer xmlFragment = new StringBuffer();
        xmlFragment.append(String.format(
            "%s<emv_tag_entry tag=\"%s\" aid=\"%s\"set_in=\"%s\">\n",
            indentString, tagHex, aid, setIn
        ));
        xmlFragment.append(indentString + indentString + valueHex + "\n");
        xmlFragment.append(indentString + "</emv_tag_entry>\n");
        return xmlFragment.toString();
    }

    public int compareTo(EmvTagEntry other) {
        int compareResult = tagHex.compareTo(other.tagHex);
        if(compareResult == 0) {
            compareResult = aid.compareTo(other.aid);
        }
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
    String m_currentAid = "not set";

    public ApduObserver() { }

    public void extractTags(CommandAndResponse carItem) {
        final int lengthOfExtraCommandBytes = Byte.toUnsignedInt(carItem.rawCommand[4]);
        final byte[] commandTlvBytes = Arrays.copyOfRange(
            carItem.rawCommand,5,5+lengthOfExtraCommandBytes
        );
        extractTags(commandTlvBytes, "terminal command " + carItem.stepName);

        final byte[] responseTlvBytes = Arrays.copyOfRange(
            carItem.rawResponse,0,carItem.rawResponse.length-2
        );
        extractTags(responseTlvBytes, "media response to " + carItem.stepName);
    }

    void extractTags(byte[] tlvBytes, String setBy) {
		TLVInputStream stream = new TLVInputStream(new ByteArrayInputStream(tlvBytes));

		try {
			while (stream.available() > 0) {
				TLV tlv = TlvUtil.getNextTLV(stream);

				if (tlv == null) {
					LOGGER.warn("TLV format error");
					break;
				} else if(tlv.getTag().isConstructed()) {
                    extractTags(tlv.getValueBytes(),setBy);
                } else {
                    EmvTagEntry newEmvTagEntry = new EmvTagEntry();

                    newEmvTagEntry.tagHex = BytesUtils.bytesToStringNoSpace(tlv.getTagBytes());
                    newEmvTagEntry.valueHex = BytesUtils.bytesToString(tlv.getValueBytes());
                    newEmvTagEntry.aid = m_currentAid;
                    newEmvTagEntry.setIn = setBy;
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
            case 0x00a4:
                int lengthOfExtraBytes = cr.rawCommand[4];
                byte[] extraBytes = Arrays.copyOfRange(cr.rawCommand,5,5+lengthOfExtraBytes);
                if(p1_p2 == 0x0400) {
                    if(Arrays.equals(extraBytes,"2PAY.SYS.DDF01".getBytes())) {
                        commandInterpretation.append("SELECT CONTACTLESS PPSE");
                    } else if(Arrays.equals(extraBytes,"1PAY.SYS.DDF01".getBytes())) {
                        commandInterpretation.append("SELECT CONTACT PPE");
                    } else {
                        commandInterpretation.append("SELECT APPLICATION BY AID ");
                        commandInterpretation.append(BytesUtils.bytesToStringNoSpace(extraBytes));
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
                break;
            case 0x80A8:
                commandInterpretation.append("GET_PROCESSING_OPTIONS");
                cr.interpretedCommand = commandInterpretation.toString();
                break;
            case 0x80CA:
                commandInterpretation.append("GET_DATA");
                cr.interpretedCommand = commandInterpretation.toString();
                break;

            case 0x00B2:
                commandInterpretation.append("READ_RECORD");
                cr.interpretedCommand = commandInterpretation.toString();
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

    void interpretResponse(CommandAndResponse cr) {
        if(cr.interpretedResponseStatus != null) {
            // If this is already filled in it describes an exception,
            // there is nothing more to be done
            return;
        }
        SwEnum swval = SwEnum.getSW(cr.rawResponse);
        if (swval != null) {
            cr.interpretedResponseStatus = swval.toString();
			cr.interpretedResponseBody = TlvUtil.prettyPrintAPDUResponse(cr.rawResponse);
        } else {
            cr.interpretedResponseStatus = "Status word not found";
            cr.interpretedResponseBody = "Not parsed";
        }
    }

    public void add(CommandAndResponse newCommandAndResponse) {
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
