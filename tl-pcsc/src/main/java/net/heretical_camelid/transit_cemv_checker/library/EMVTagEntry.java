package net.heretical_camelid.transit_cemv_checker.library;

/**
 * EMV tags can be sent in both commands and responses.
 * Note that nearly all EMV tags are sent and received during
 * the processing of a specific application - if the card contains
 * multiple applications there is no guarantee that a given tag
 * contains the same value in the context of one AID that it does
 * in the context of another or even that the same tags are 
 * defined in every context.
 * In practice, for most tags, we expect that they will have the
 * same value for all AIDs if defined, but it will be common for
 * some tags to be defined for some AIDs but not for others, but
 * the 'scope' member of this class will enable traceability of 
 * tag values set during the command/response exchange to the AID 
 * which the value is associated with.
 */
class EMVTagEntry implements Comparable<EMVTagEntry> {
    String tagHex = null;
    String source = null;
    String scope = null;
    String valueHex = null;

    String toXmlFragment(String indentString) {
        StringBuffer xmlFragment = new StringBuffer();

        xmlFragment.append(String.format(
            "%s<emv_tag_entry tag=\"%s\"", indentString, tagHex
        ));
        if(source!=null) {
            xmlFragment.append(String.format(" source=\"%s\"", source));
        }
        if(scope!=null) {
            xmlFragment.append(String.format(" scope=\"%s\"", scope));
        }
        xmlFragment.append(">\n");
        
        xmlFragment.append(indentString + indentString + valueHex + "\n");
        
        xmlFragment.append(indentString + "</emv_tag_entry>\n");
        
        return xmlFragment.toString();
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("[EMVTagEntry: tag=" + tagHex);
        if(source != null) {
            sb.append(" source=" + source);
        }
        if(scope != null) {
            sb.append(" scope=" + scope);
        }
        sb.append(
            " value=" + 
            valueHex.replace(" ","") + 
            "]"
        );
        return sb.toString();
    }

    public int compareTo(EMVTagEntry other) {
        int compareResult = tagHex.compareTo(other.tagHex);
        if(compareResult == 0) {
            if(scope!=null && other.scope!=null) {
                compareResult = scope.compareTo(other.scope);
            } else if(scope!=null) {
                compareResult = +1;
            } else if(other.scope!=null) {
                compareResult= -1;
            } else {
                // both scopes are null
                // compareResult is already set to 0 which is correct
            }
        }
        return compareResult;
    }
}