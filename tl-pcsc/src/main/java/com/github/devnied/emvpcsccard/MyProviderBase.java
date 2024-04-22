package com.github.devnied.emvpcsccard;

import java.nio.ByteBuffer;
import java.util.ArrayList;

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

        String toXmlFragment(String fragmentName) {
            StringBuffer xmlFragment = new StringBuffer();
            if(fragmentName==null) {
                xmlFragment.append("    <command_and_response>\n");
            } else {
                xmlFragment.append(String.format("    <command_and_response name=\"%s\">\n",fragmentName));
            }
            if(rawCommand!=null) {
                xmlFragment.append(String.format(
                    "        <raw_command>%s</raw_command>\n",
                    BytesUtils.bytesToString(rawCommand)
                ));
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
                    commandInterpretation.append("SELECT_BY_NAME");
                    cr.interpretedCommand = commandInterpretation.toString();
                } else {
                    // Don't expect this
                    cr.interpretedCommand = "SELECT_BY_????";
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
		LOGGER.info("Command and response:\n " + newCommandAndResponse.toXmlFragment(null));

        m_commandsAndResponses.add(newCommandAndResponse);

		return ret;
	}

	abstract public byte[] getAt();    

}
