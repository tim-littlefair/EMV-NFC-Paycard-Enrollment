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

public abstract class MyProviderBase implements IProvider {
    class CommandAndResponse {
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

    ArrayList<CommandAndResponse> m_commandsAndResponses = new ArrayList<CommandAndResponse>();

	/**
	 * Class logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(MyProviderBase.class);    

	/**
	 * Buffer
	 */
	private final ByteBuffer buffer = ByteBuffer.allocate(1024);

    protected abstract byte[] implementationTransceive(final byte[] pCommand, ByteBuffer receiveBuffer) throws CommunicationException;

    private void interpretCommand(CommandAndResponse cr) {
        int cla_ins = BytesUtils.byteArrayToInt(cr.rawCommand,0,2);
        int p1_p2 = BytesUtils.byteArrayToInt(cr.rawCommand,2,2);
        StringBuffer commandInterpretation = new StringBuffer();

        switch(cla_ins) {
            case 0x00a4:
                if(p1_p2 == 0x0400) {
                    byte[] aidBytes = Arrays.copyOfRange(cr.rawCommand,5,5+cr.rawCommand[4]);
                    commandInterpretation.append("SELECT_BY_AID ");
                    commandInterpretation.append(BytesUtils.bytesToStringNoSpace(aidBytes));
                    cr.interpretedCommand = commandInterpretation.toString();
                } else {
                    // Don't expect this but ISO 7816 does define other modes of select
                    // selected via p1_p2 so log in case we ever see them used.
                    byte[] trailingBytes = Arrays.copyOfRange(cr.rawCommand,4,cr.rawCommand.length-4);
                    commandInterpretation.append("SELECT_BY_???? ");
                    commandInterpretation.append(
                        String.format("p1_p2=%04x trailing_bytes=%s", 
                        p1_p2, BytesUtils.bytesToString(trailingBytes)
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
    }

    private void interpretResponse(CommandAndResponse cr) {
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

    @Override
	public byte[] transceive(final byte[] pCommand) throws CommunicationException {
        CommandAndResponse newCommandAndResponse = new CommandAndResponse();
		byte[] ret = null;
		buffer.clear();
        newCommandAndResponse.rawCommand = pCommand;
		try {
            ret = implementationTransceive(pCommand, buffer);
            newCommandAndResponse.rawResponse = ret;
		} catch (CommunicationException e) {
            newCommandAndResponse.interpretedResponseStatus = "Exception: " + e.getMessage();
		}
        interpretCommand(newCommandAndResponse);
        interpretResponse(newCommandAndResponse);

        m_commandsAndResponses.add(newCommandAndResponse);

        LOGGER.info(newCommandAndResponse.toXmlFragment(null));

		return ret;
	}

	abstract public byte[] getAt();    

}
