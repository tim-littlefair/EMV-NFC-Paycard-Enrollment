package com.github.devnied.emvpcsccard;

import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.devnied.emvnfccard.iso7816emv.EmvTags;
import com.github.devnied.emvnfccard.iso7816emv.ITerminal;
import com.github.devnied.emvnfccard.iso7816emv.TagAndLength;
import com.github.devnied.emvnfccard.iso7816emv.TerminalTransactionQualifiers;
import com.github.devnied.emvnfccard.model.enums.CountryCodeEnum;
import com.github.devnied.emvnfccard.model.enums.CurrencyEnum;
import com.github.devnied.emvnfccard.model.enums.TransactionTypeEnum;

import fr.devnied.bitlib.BytesUtils;

public class OfflineTransitTerminal implements ITerminal {
    private static final Logger LOGGER = LoggerFactory.getLogger(OfflineTransitTerminal.class);
    /**
     * Random
     */
    private static final SecureRandom random = new SecureRandom();

    /**
     * Country code
     */
    private CountryCodeEnum countryCode;

    public OfflineTransitTerminal() {
        countryCode = CountryCodeEnum.FR;
    }

    private void setArrayBit(byte[] array, int byteIndex, int bitIndex, boolean bitValue) {
        // The parameters to this function are intended to conform 
        // to EMV conventions, i.e. both bytes and bits are indexed 
        // from 1.
        array[byteIndex-1] = BytesUtils.setBit(array[byteIndex-1], bitIndex-1, bitValue); 
    }

    /**
     * Method used to construct value from tag and length
     *
     * @param pTagAndLength
     *            tag and length value
     * @return tag value in byte
     */
    @SuppressWarnings("unused")
    @Override
    public byte[] constructValue(final TagAndLength pTagAndLength) {
        byte ret[] = new byte[pTagAndLength.getLength()];
        byte val[] = null;
        if (pTagAndLength.getTag() == EmvTags.TERMINAL_TRANSACTION_QUALIFIERS) {
            if(false) {
                val = new byte[pTagAndLength.getLength()];

                // references:
                // https://paymentcardtools.com/emv-tag-decoders/ttq
                // EMV: 
                // Visa: EMV Book C.3 v2.11 p113-114
                // TODO: determine whether this needs to be different between Visa 
                // and other brands

                setArrayBit(val,1, 8, false); // MSD not supported
                // ret[0] bit 7 RFU = 0 
                setArrayBit(val,1, 6, true);  // Visa: qVSDC supported
                setArrayBit(val,1, 5, false); // Contact not supported
                // Transit terminals are do all taps offline, but might pretend to 
                // be online-capable so that the card generates an ARQC for 
                // deferred authorisation at the payment gateway.
                setArrayBit(val,1, 4, false); // not offline only
                setArrayBit(val,1, 3, false); // Online PIN not supported
                setArrayBit(val,1, 2, false); // Signature not supported
                setArrayBit(val,1, 1, true);  // ODA for online supported

                setArrayBit(val,2, 8, true);  // Online cryptogram required
                // setting CVM required by default to trigger CDCVM (i.e. mobile unlock)
                setArrayBit(val,2, 7, true);  // CVM required
                setArrayBit(val,2, 6, false); // Offline PIN not supported
                // byte 2 bits 5-1 RFU = 0 for Visa
                // TODO: Work out whether this is OK for other brands

                setArrayBit(val,3, 8, false);  // Issuer updates not supported
                // Turn on CDCVM so that we can see whether it is triggered
                setArrayBit(val,3, 7, true);   // Consumer device CDM supported
                // byte 3 bits 6-1 RFU = 0 for Visa
                // TODO: Work out whether this is OK for other brands

                // byte 4 all bits RFU = 0
            } else {
                TerminalTransactionQualifiers terminalQual = new TerminalTransactionQualifiers();

                // byte 1 bit 8: MSD not supported
                terminalQual.setMagneticStripeSupported(false);

                // byte 1 bit 7: RFU, must be zero

                // byte 1 bit 6: contactless EMV/qVSDC is supported
                terminalQual.setContactlessEMVmodeSupported(true);

                // byte 1 bit 5: contact EMV not supported
                terminalQual.setContactEMVsupported(false);							

                // see comment in TerminalTransactionQualifiers
                // contactless VSDC != qVSDC
                // if contactless VSDC is enabled qVSDC must be disabled
                terminalQual.setContactlessVSDCsupported(false); 

                // byte 1 bit 4: transit terminals validate taps offline
                // but are not declared as offline only reader as they
                // require the medium to issue an ARQC for deferred 
                // authorisation at the payment gateway
                terminalQual.setReaderIsOfflineOnly(false);

                // byte 1 bit 3: online PIN not supported
                terminalQual.setOnlinePINsupported(false);

                // byte 1 bit 2: signature not supported
                terminalQual.setSignatureSupported(false);


                // Upstream TerminalTransactionQualifiers lacks the ability to set byte 1 bit 1
                // to declare ODA support
                // TODO: resolve this

                // byte 2 bit 8: Online cryptogram is required for deferred authorisation
                terminalQual.setOnlineCryptogramRequired(true);

                // byte 2 bit 7: CVM not required by terminal
                terminalQual.setCvmRequired(false);

                // byte 2 bit 6: Offline PIN not supported
                terminalQual.setContactChipOfflinePINsupported(false);

                // byte 2 bits 5-1: RFU, must be zero


                // byte 3 bit 8: Issuer update processing not supported
                terminalQual.setIssuerUpdateProcessingSupported(false);

                // byte 3 bit 7: CDCVM (i.e. unlocking mobile device to make payment) supported
                terminalQual.setConsumerDeviceCVMsupported(true);

                // byte 3 bits 6-1: RFU must be zero


                // byte 4 bits 8-1: RFU must be zero

                val = terminalQual.getBytes();

                // Updating bits which devnied's TerminalTransactionQualifiers doesn't allow 
                // me to control
                // val[0] = (byte)(val[0] & 0x80); // byte 1 bit 7 is RFU required to be equal to zero BUT THIS TRIGGERS FAILURE
                // val[0] = (byte)(val[0] & 0x01);    // byte 1 bit 1 declares support for ODA for online authorizations

            }
        } else if (pTagAndLength.getTag() == EmvTags.TERMINAL_COUNTRY_CODE) {
            val = BytesUtils.fromString(StringUtils.leftPad(String.valueOf(countryCode.getNumeric()), pTagAndLength.getLength() * 2,
                    "0"));
        } else if (pTagAndLength.getTag() == EmvTags.TRANSACTION_CURRENCY_CODE) {
            val = BytesUtils.fromString(StringUtils.leftPad(String.valueOf(CurrencyEnum.find(countryCode, CurrencyEnum.EUR).getISOCodeNumeric()),
                    pTagAndLength.getLength() * 2, "0"));
        } else if (pTagAndLength.getTag() == EmvTags.TRANSACTION_DATE) {
            SimpleDateFormat sdf = new SimpleDateFormat("yyMMdd");
            val = BytesUtils.fromString(sdf.format(new Date()));
        } else if (pTagAndLength.getTag() == EmvTags.TRANSACTION_TYPE || pTagAndLength.getTag() == EmvTags.TERMINAL_TRANSACTION_TYPE) {
            val = new byte[] { (byte) TransactionTypeEnum.PURCHASE.getKey() };
        } else if (pTagAndLength.getTag() == EmvTags.AMOUNT_AUTHORISED_NUMERIC) {
            val = BytesUtils.fromString("01");
        } else if (pTagAndLength.getTag() == EmvTags.TERMINAL_TYPE) {
            val = new byte[] { 0x22 };
        } else if (pTagAndLength.getTag() == EmvTags.TERMINAL_CAPABILITIES) {
            val = new byte[] { (byte) 0xE0, (byte) 0xA0, 0x00 };
        } else if (pTagAndLength.getTag() == EmvTags.ADDITIONAL_TERMINAL_CAPABILITIES) {
            val = new byte[] { (byte) 0x8e, (byte) 0, (byte) 0xb0, 0x50, 0x05 };
        } else if (pTagAndLength.getTag() == EmvTags.DS_REQUESTED_OPERATOR_ID) {
            val = BytesUtils.fromString("7A45123EE59C7F40");
        } else if (pTagAndLength.getTag() == EmvTags.UNPREDICTABLE_NUMBER) {
            random.nextBytes(ret);
        } else if (pTagAndLength.getTag() == EmvTags.MERCHANT_TYPE_INDICATOR) {
            val = new byte[] { 0x01 };
        } else if (pTagAndLength.getTag() == EmvTags.TERMINAL_TRANSACTION_INFORMATION) {
            val = new byte[] { (byte) 0xC0, (byte) 0x80, 0 };
        }
        if (val != null) {
            System.arraycopy(val, 0, ret, Math.max(ret.length - val.length, 0), Math.min(val.length, ret.length));
        }            
        LOGGER.info(
            pTagAndLength.toString() + ": " + BytesUtils.bytesToString(ret)
        );
        return ret;
    }
}
