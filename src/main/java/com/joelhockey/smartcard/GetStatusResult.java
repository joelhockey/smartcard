/* 
 * Copyright 2009 Joel Hockey (joel.hockey@gmail.com).  All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 * 
 * THIS SOURCE CODE IS PROVIDED BY JOEL HOCKEY WITH A 30-DAY MONEY BACK
 * GUARANTEE.  IF THIS CODE DOES NOT MEAN WHAT IT SAYS IT MEANS WITHIN THE
 * FIRST 30 DAYS, SIMPLY RETURN THIS CODE IN ORIGINAL CONDITION FOR A PARTIAL
 * REFUND.  IN ADDITION, I WILL REFORMAT THIS CODE USING YOUR PREFERRED
 * BRACE-POSITIONING AND INDENTATION.  THIS WARRANTY IS VOID IF THE CODE IS
 * FOUND TO HAVE BEEN COMPILED.  NO FURTHER WARRANTY IS OFFERED.
 */

package com.joelhockey.smartcard;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.joelhockey.codec.Hex;

public class GetStatusResult {
    private static final Map<Integer, String> ISSUER_SECURITY_DOMAIN_LIFE_CYCLE_STATE = new HashMap<Integer, String>();
    private static final int[] PRIV_MASKS =    {0x80, 0xc1, 0xa0, 0x10, 0x08, 0x04, 0x02, 0xc1};
    private static final int[] PRIV_EXPECTED = {0x80, 0xc0, 0xa0, 0x10, 0x08, 0x04, 0x02, 0xc1};
    private static final String[] PRIV_NAMES = "Security Domain,DAP Verification,Delegated Management,Card lock,Card terminate,Default Selected,CVM management,Mandated DAP Verification".split(",");
    private static final Map<String, String> AID_DESC = new HashMap<String, String>();
    
    static {
        ISSUER_SECURITY_DOMAIN_LIFE_CYCLE_STATE.put(0x01, "OP_READY");
        ISSUER_SECURITY_DOMAIN_LIFE_CYCLE_STATE.put(0x07, "INITIALIZED");
        ISSUER_SECURITY_DOMAIN_LIFE_CYCLE_STATE.put(0x0f, "SECURED");
        ISSUER_SECURITY_DOMAIN_LIFE_CYCLE_STATE.put(0xef, "CARD_LOCKED");
        ISSUER_SECURITY_DOMAIN_LIFE_CYCLE_STATE.put(0xff, "TERMINATED");
        
        AID_DESC.put("A0000000030000",      "visa.openplatform");
        AID_DESC.put("A0000000035350",      "Security Domain");
        AID_DESC.put("A000000018434D00",    "Gemalto Card Manager");
        AID_DESC.put("A0000000620001",      "java.lang");
        AID_DESC.put("A0000000620002",      "java.io");
        AID_DESC.put("A0000000620003",      "java.rmi");
        AID_DESC.put("A0000000620101",      "javacard.framework");
        AID_DESC.put("A000000062010101",    "javacard.framework.service");
        AID_DESC.put("A0000000620102",      "javacard.security");
        AID_DESC.put("A0000000620201",      "javacardx.crypto");
        AID_DESC.put("A00000015100",        "org.globalplatform");
        AID_DESC.put("E82881C11702",        "ISO24727 Alpha");
    }
    
    /** Issuer Security Domain. */
    public AppRecord isd = new AppRecord();
    /** Applications. */
    public List<AppRecord> apps = new ArrayList<AppRecord>();
    /** Load Files. */
    public List<LoadFileRecord> loadFiles = new ArrayList<LoadFileRecord>();
    
    /** @return formatted string */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        // card mgr
        String aid = Hex.b2s(isd.aid, 0, isd.aid.length, true);
        String aidDesc = AID_DESC.get(aid) != null ? AID_DESC.get(aid) : "";
        String lc = ISSUER_SECURITY_DOMAIN_LIFE_CYCLE_STATE.get(isd.lifeCycleState);
        sb.append(String.format("%12s : %-11s : %-18s : %-26s : %s\n", "Card Manager", lc, aid, aidDesc, privList(isd.privs)));
        
        // apps
        for (AppRecord app : apps) {
            aid = Hex.b2s(app.aid, 0, app.aid.length, true);
            aidDesc = AID_DESC.get(aid) != null ? AID_DESC.get(aid) : "";
            lc = "?";
            if ((app.lifeCycleState & 0xff) == 0x03) {
                lc = "INSTALLED";
            } else if ((app.lifeCycleState & 0x85) == 0x05) {
                lc = "SELECTABLE";
            } else if ((app.lifeCycleState & 0x83) == 0x83) {
                lc = "LOCKED";
            }
            sb.append(String.format("%12s : %-11s : %-18s : %-26s : %s\n", "Application", lc, aid, aidDesc, privList(app.privs)));
        }
        
        // load files
        for (LoadFileRecord lf : loadFiles) {
            aid = Hex.b2s(lf.aid, 0, lf.aid.length, true);
            aidDesc = AID_DESC.get(aid) != null ? AID_DESC.get(aid) : "";
            lc = "?";
            if ((lf.lifeCycleState & 0xff) == 0x01) {
                lc = "LOADED";
            }      
            sb.append(String.format("%12s : %-11s : %-18s : %-26s\n", "Load File", lc, aid, aidDesc));
            for (byte[] moduleAid : lf.moduleAids) {
                aid = Hex.b2s(moduleAid, 0, moduleAid.length, true);
                sb.append(String.format("%12s : %-11s : %-18s\n", "Module", "", aid));
            }
        }
        return sb.toString();
    }
    
    /**
     * Format priv list into string.
     * @param privs privileges
     * @return formatted string
     */
    private String privList(int privs) {
        StringBuilder sb = new StringBuilder();
        String sep = "";
        for (int i = 0; i < PRIV_MASKS.length; i++) {
            if ((privs & PRIV_MASKS[i]) == PRIV_EXPECTED[i]) {
                sb.append(sep).append(PRIV_NAMES[i]);
                sep = "|";
            }
        }
        return sb.toString();
    }

    /** Application Record struct.  GP v2.1.1 9.4.3.1 Table 9-22 */
    public static class AppRecord {
        public byte[] aid;
        public int lifeCycleState;
        public int privs;
    }
    
    /** Load File Record struct.  GP v2.1.1 9.4.3.1 Table 9-24 */
    public static class LoadFileRecord {
        public byte[] aid;
        public int lifeCycleState;
        public int privs;
        public List<byte[]> moduleAids = new ArrayList<byte[]>();
    }
}
