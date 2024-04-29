package com.github.devnied.emvpcsccard;

import java.util.List;
import java.nio.file.Paths;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import javax.smartcardio.TerminalFactory;
import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardChannel;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.devnied.emvnfccard.exception.CommunicationException;
import com.github.devnied.emvnfccard.model.EmvCard;
import com.github.devnied.emvnfccard.parser.EmvTemplate;
import com.github.devnied.emvnfccard.parser.EmvTemplate.Config;

@SuppressWarnings("restriction")
public class Main {
	private static final Logger LOGGER = LoggerFactory.getLogger(Main.class);

	public static void main(final String[] args) throws CardException, CommunicationException {

		TerminalFactory factory = TerminalFactory.getDefault();
		List<CardTerminal> terminals = factory.terminals().list();
		if (terminals.isEmpty()) {
			throw new CardException("No card terminals available");
		}

		ApduObserver apduObserver = new ApduObserver();

		if (terminals != null && !terminals.isEmpty()) {
			// Use the first terminal
			CardTerminal terminal = terminals.get(0);

			if (terminal.waitForCardPresent(0)) {
				// Connect with the card
				Card card = terminal.connect("*");
				LOGGER.info("card: " + card);

				// Create provider
				PcscProvider provider = new PcscProvider(card, apduObserver);
				
				// Define config
				Config config = EmvTemplate.Config()
						.setContactLess(true)
						.setReadAllAids(true)
						.setReadTransactions(false)
						.setReadAt(false)
						// Reading CPLC is presently disabled for two reasons:
						// 1) It is not interesting for the purposes of this application
						// 2) With some of the cards I have to hand, devnied's implementation 
						//    in v3.0.2-SNAPSHOT of this throws an exception because the 
						//    two byte pattern 0xFF 0xFF is not accepted as a placeholder 
						//    for an undefined date.  I plan to raise a PR on devnied's
						//    github project to tolerate this value in the same way the value
						//    0x00 0x00 is tolerated.
						.setReadCplc(false)
						// This application substitutes an alternate implementation of 
						// the parser, see the comment on MyParser.extractCommonsCardData
						// for why the local implementation is chosen over devnied's 
						// EmvParser.
						.setRemoveDefaultParsers(true);
				
				// Create Parser
				EmvTemplate template = EmvTemplate.Builder() //
						.setProvider(provider) // Define provider
						.setConfig(config) // Define config
						//.setTerminal(terminal) (optional) you can define a custom terminal implementation to create APDU
						.build();
				template.addParsers(new MyParser(template, apduObserver));
				
				// Read card
				EmvCard emvCard = template.readEmvCard();
				
				// Disconnect the card
				card.disconnect(false);

				// At this point apduObserver contains raw data relating to the 
				// transaction - before we can dump this in a PCI-compliant 
				// environment we need to mask all occurrences of the PAN
				// and the cardholder name.
				boolean pciMaskingOk = apduObserver.pciMaskAccountData();

				if(pciMaskingOk == true) {
					// TODO?: Allow args to control XML output directory/filename
					String outDirName = "_work/";
					String outFileName = apduObserver.mediumStateId() + ".xml";
					try {
						Files.createDirectories(Paths.get(outDirName));
						File outFile = new File(outDirName+outFileName);
						FileWriter outFileWriter = new FileWriter(outFile.getAbsoluteFile()); 
						outFileWriter.write(apduObserver.toXmlString());
						outFileWriter.close();
					} catch (IOException e) {
						LOGGER.error("Problem writing file out");
						e.printStackTrace();
					}
					LOGGER.info("Tap has been dumped to " + outDirName+outFileName);
				} else {
					LOGGER.info("Tap has not been dumped because PCI masking failed");
				}
			}
		} else {
			LOGGER.error("No pcsc terminal found");
		}
	}
}
