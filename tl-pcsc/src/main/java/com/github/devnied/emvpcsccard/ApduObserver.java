package com.github.devnied.emvpcsccard;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.devnied.emvnfccard.enums.SwEnum;
import com.github.devnied.emvnfccard.parser.IProvider;
import com.github.devnied.emvnfccard.utils.TlvUtil;
import com.github.devnied.emvnfccard.exception.CommunicationException;

import fr.devnied.bitlib.BytesUtils;
class CommandAndResponse {
    String carName = null;
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

    String toXmlFragment(String fragmentName) {
        final String _INDENT_STRING = "    ";
        StringBuffer xmlFragment = new StringBuffer();

        if(fragmentName==null) {
            xmlFragment.append("    <command_and_response>\n");
        } else {
            xmlFragment.append(String.format("    <command_and_response name=\"%s\">\n",fragmentName));
        }

        if(rawCommand!=null) {
            appendIndentedHexNode(
                xmlFragment, "raw_command", 
                BytesUtils.bytesToString(rawCommand),2,_INDENT_STRING
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

public class ApduObserver {
    ArrayList<CommandAndResponse> m_commandsAndResponses = new ArrayList<CommandAndResponse>();

    public ApduObserver() { }

    void interpretCommand(CommandAndResponse cr) {
        int cla_ins = BytesUtils.byteArrayToInt(cr.rawCommand,0,2);
        int p1_p2 = BytesUtils.byteArrayToInt(cr.rawCommand,2,2);
        StringBuffer commandInterpretation = new StringBuffer();

        switch(cla_ins) {
            case 0x00a4:
                int lengthOfExtraBytes = cr.rawCommand[4];
                byte[] extraBytes = Arrays.copyOfRange(cr.rawCommand,5,5+lengthOfExtraBytes);
                if(p1_p2 == 0x0400) {
                    if(extraBytes == "2PAY.SYS.DDF01".getBytes()) {
                        commandInterpretation.append("SELECT CONTACTLESS PPSE");
                    } else if(extraBytes == "1PAY.SYS.DDF01".getBytes()) {
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
                    cr.carName = commandInterpretation.toString();
                    cr.interpretedCommand = commandInterpretation.toString();
                }
                break;
            case 0x80A8:
                commandInterpretation.append("GET_PROCESSING_OPTIONS");
                cr.carName = commandInterpretation.toString();
                cr.interpretedCommand = commandInterpretation.toString();
                break;
            case 0x80CA:
                commandInterpretation.append("GET_DATA");
                cr.carName = commandInterpretation.toString();
                cr.interpretedCommand = commandInterpretation.toString();
                break;

            case 0x00B2:
                commandInterpretation.append("READ_RECORD");
                cr.carName = commandInterpretation.toString();
                cr.interpretedCommand = commandInterpretation.toString();
                break;

            default:
                cr.carName = commandInterpretation.toString();
                cr.interpretedCommand = String.format("Unexpected CLA/INS %04x", cla_ins);
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
        StringBuffer xmlBuffer = new StringBuffer();
        xmlBuffer.append("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
        xmlBuffer.append("<emv_medium>\n");
        for(CommandAndResponse carItem: m_commandsAndResponses) {
            xmlBuffer.append(carItem.toXmlFragment(null));
        }
        xmlBuffer.append("</emv_medium>\n");
        return xmlBuffer.toString();
    }

}
