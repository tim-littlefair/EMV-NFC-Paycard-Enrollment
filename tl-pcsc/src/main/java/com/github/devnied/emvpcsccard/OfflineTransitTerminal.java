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

    // Values we might want to override...
    private CountryCodeEnum m_countryCode;
    private CurrencyEnum m_currencyCode;
    private byte[] m_terminalCapabilities;
    private byte[] m_additionalTerminalCapabilities;

    public OfflineTransitTerminal() {
        m_countryCode = CountryCodeEnum.AU;
        m_currencyCode = CurrencyEnum.AUD;
        m_terminalCapabilities = new byte[] { (byte) 0x00, (byte) 0x08, (byte) 0xC8 };
        m_additionalTerminalCapabilities = new byte[] { (byte) 0x62, (byte) 0x00, (byte) 0x00, 0x10, 0x00 };
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
            val = new byte[4];

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
            setArrayBit(val,2, 7, false); // CVM not required by terminal
            setArrayBit(val,2, 6, false); // Offline PIN not supported
            // byte 2 bits 5-1 RFU = 0 for Visa
            // TODO: Work out whether this is OK for other brands

            setArrayBit(val,3, 8, false);  // Issuer updates not supported
            // Turn on CDCVM so that we can see whether it is triggered
            setArrayBit(val,3, 7, true);   // Consumer device CDM supported

            // byte 3 bits 6-1 RFU = 0 for Visa

            // TODO: Work out whether this is OK for other brands

            // byte 4 all bits RFU = 0
        } else if (pTagAndLength.getTag() == EmvTags.TERMINAL_COUNTRY_CODE) {
            val = BytesUtils.fromString(StringUtils.leftPad(String.valueOf(m_countryCode.getNumeric()), pTagAndLength.getLength() * 2,
                    "0"));
        } else if (pTagAndLength.getTag() == EmvTags.TRANSACTION_CURRENCY_CODE) {
            val = BytesUtils.fromString(StringUtils.leftPad(String.valueOf(CurrencyEnum.find(m_countryCode, m_currencyCode).getISOCodeNumeric()),
                    pTagAndLength.getLength() * 2, "0"));
        } else if (pTagAndLength.getTag() == EmvTags.TRANSACTION_DATE) {
            SimpleDateFormat sdf = new SimpleDateFormat("yyMMdd");
            val = BytesUtils.fromString(sdf.format(new Date()));
        } else if (pTagAndLength.getTag() == EmvTags.TRANSACTION_TYPE || pTagAndLength.getTag() == EmvTags.TERMINAL_TRANSACTION_TYPE) {
            val = new byte[] { (byte) TransactionTypeEnum.PURCHASE.getKey() };
        } else if (pTagAndLength.getTag() == EmvTags.AMOUNT_AUTHORISED_NUMERIC) {
            val = BytesUtils.fromString("00");
        } else if (pTagAndLength.getTag() == EmvTags.TERMINAL_TYPE) {
            val = new byte[] { 0x22 };
        } else if (pTagAndLength.getTag() == EmvTags.TERMINAL_CAPABILITIES) {
            val = m_terminalCapabilities;
        } else if (pTagAndLength.getTag() == EmvTags.ADDITIONAL_TERMINAL_CAPABILITIES) {
            val = m_additionalTerminalCapabilities;
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
