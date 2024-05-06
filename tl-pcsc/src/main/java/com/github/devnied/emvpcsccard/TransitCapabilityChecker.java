package com.github.devnied.emvpcsccard;

import java.util.TreeMap;
import java.util.TreeSet;

import fr.devnied.bitlib.BytesUtils;

public class TransitCapabilityChecker {
    TreeSet<String> m_appSelectionContexts;
    TreeMap<String,String> m_emvTagEntryIndex;

    public TransitCapabilityChecker(ApduObserver apduObserver) {
        m_appSelectionContexts = new TreeSet<>();
        m_emvTagEntryIndex = new TreeMap<>();
        for(EmvTagEntry ete: apduObserver.m_emvTagEntries) {
            String eteScope = ete.scope;
            if(eteScope == null) {
                // counters - maybe relevant for velocity checks
            } else if(!m_appSelectionContexts.contains(eteScope)) {
                m_appSelectionContexts.add(eteScope);
            }
            String eteKey = ete.scope + "." + ete.tagHex;
            m_emvTagEntryIndex.put(eteKey,ete.valueHex);
        }
    }

    public String capabilityReport() {
        StringBuilder capabilityNotes = new StringBuilder();
        for(String ascKey: m_appSelectionContexts) {
            checkCapability(ascKey,capabilityNotes);
        }
        return capabilityNotes.toString();
    }

    private void checkCapability(String ascKey, StringBuilder capabilityNotes) {

        String[] _OVERALL_CHECK_OUTCOMES = {
            "No impediments to transit use discovered",
            "Potential impediments to transit use discovered",
            "Fatal impediments to transit use discovered"
        };
        int outcomeIndex = 0;

        capabilityNotes.append("Application configuration " + ascKey + "\n");

        outcomeIndex = checkODACapability(ascKey, outcomeIndex, capabilityNotes);
        outcomeIndex = checkUsageRestrictions(ascKey, outcomeIndex, capabilityNotes);

        capabilityNotes.append(_OVERALL_CHECK_OUTCOMES[outcomeIndex] + "\n");
    }

    private String getValueHex(String scope, String tagHexString) {
        return m_emvTagEntryIndex.get(scope + "." + tagHexString);
    }

    private byte[] getValueBytes(String scope, String tagHexString) {
        String valueHex = getValueHex(scope, tagHexString);
        if(valueHex == null) {
            return BytesUtils.fromString(valueHex);
        }
        return null;
    }


    private int checkODACapability(
        String ascKey, int outcomeIndex, StringBuilder capabilityNotes
    ) {
        // AIP = Application Interchange Profile
        byte[] aipValueBytes = getValueBytes(ascKey,"82");

        // CAPK = Certificate Authority Public Key
        String capkIndexHex = getValueHex(ascKey, "8F");

        if(aipValueBytes == null) {
            capabilityNotes.append("AIP not found - unable to check if CDA supported");
            outcomeIndex = Math.max(outcomeIndex,1);
        } else if(aipValueBytes.length != 2) {
            capabilityNotes.append("AIP has unexpected length => unable to check if CDA supported");
            outcomeIndex = Math.max(outcomeIndex,1);
        } else if( (aipValueBytes[0]&0x01) != 0x01 ) {
            capabilityNotes.append("AIP byte 1 bit 1 not set => CDA not supported");
            outcomeIndex = 2;
        } else if( (aipValueBytes[1]&(byte)0x80) != 0x80) {
            capabilityNotes.append("AIP byte 2 bit 8 not set => MSD only, EMV not supported");
            outcomeIndex = 2;
        }

        if(outcomeIndex<2 && capkIndexHex == null) {
            capabilityNotes.append(
                "ODA not supported - CAPK index not found\n"
            );
            outcomeIndex = 2;
        } else {
            capabilityNotes.append(
                "ODA supported - using CAPK #" + capkIndexHex + "\n"
            );
        }

        return outcomeIndex;
    }

    private int checkUsageRestrictions(String ascKey, int outcomeIndex, StringBuilder capabilityNotes) {
        // TODO: Implement this
        return outcomeIndex;
    }
}
