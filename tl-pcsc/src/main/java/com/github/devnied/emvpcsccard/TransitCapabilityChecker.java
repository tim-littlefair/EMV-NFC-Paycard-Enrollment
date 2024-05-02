package com.github.devnied.emvpcsccard;

import java.util.TreeMap;
import java.util.TreeSet;

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

    private int checkODACapability(
        String ascKey, int outcomeIndex, StringBuilder capabilityNotes
    ) {
        // CAPK = Certificate Authority Public Key
        String capkIndexKey = ascKey + "." + "8F";
        String capkIndexValue = m_emvTagEntryIndex.get(capkIndexKey);
        // SDAD = Signed Dynamic Application Data
        String sdadKey = ascKey + "." + "9F48";
        String sdadValue = m_emvTagEntryIndex.get(sdadKey);

        if(capkIndexValue == null) {
            capabilityNotes.append(
                "ODA not supported -\n CAPK index not found\n"
            );
            outcomeIndex = 2;
        } else if (sdadValue == null) {
            capabilityNotes.append(
                "ODA not supported -\n signed dynamic application data not found\n"
            );
            outcomeIndex = 2;
        } else {
            capabilityNotes.append(
                "ODA supported - using CAPK #" + capkIndexValue + "\n"
            );
        }

        return outcomeIndex;
    }

    private int checkUsageRestrictions(String ascKey, int outcomeIndex, StringBuilder capabilityNotes) {
        // TODO: Implement this
        return outcomeIndex;
    }
}
