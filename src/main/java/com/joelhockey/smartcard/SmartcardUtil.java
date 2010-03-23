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

import com.joelhockey.codec.Buf;
import com.joelhockey.codec.Hex;

public class SmartcardUtil {
    
    /**
     * Format APDU.
     * @param cla cla
     * @param ins ins
     * @param p1 p1
     * @param p2 p2
     * @param data data
     * @param le le
     * @return formatted APDU
     */
    public static byte[] formatAPDU(int cla, int ins, int p1, int p2, byte[] data, Integer le) {
        int lc = data == null ? 0 : data.length;
        byte[] lcbuf; // holds Lc - 1 or 3 bytes
        byte[] lebuf = null; // holds Le, 0, 1, or 2 bytes
        if (lc <= 255) {
            // single byte Lc and Le
            lcbuf = new byte[] {(byte) lc};
            if (le != null) {
                lebuf = new byte[] {(byte) le.intValue()};
            }
        } else {
            // extended lengths (3 bytes for Lc, 2 bytes for Le)
            lcbuf = new byte[] {0, (byte) (lc >> 8), (byte) lc};
            if (le != null) {
                lebuf = new byte[] {(byte) (le.intValue() >> 8), (byte) le.intValue()};
            }
        }
        return Buf.cat(new byte[] {(byte) cla, (byte) ins, (byte) p1, (byte) p2}, lcbuf, data, lebuf);
    }
    
    /**
     * Translate from {@link Smartcard#transmit(byte[])}
     * to {@link Smartcard#transmit(int, int, int, int, byte[], Integer)}.
     * @param card card to call {@link Smartcard#transmit(int, int, int, int, byte[], Integer)}
     * @param apdu apdu
     * @return APDURes from invoking {@link Smartcard#transmit(byte[])}
     * @throws SmartcardException if error
     */
    public static APDURes transmit(Smartcard card, byte[] apdu) throws SmartcardException {
        if (apdu == null || apdu.length < 4) {
            throw new SmartcardException("APDU must be at least 4 bytes, got apdu: " + Hex.b2s(apdu));
        }
        int cla = apdu[0] & 0xff;
        int ins = apdu[1] & 0xff;
        int p1 = apdu[2] & 0xff;
        int p2 = apdu[3] & 0xff;
        // case 1
        if (apdu.length == 4) {
            return card.transmit(cla, ins, p1, p2, null, null);

        // case 2s
        } else if (apdu.length == 5) {
            return card.transmit(cla, ins, p1, p2, null, apdu[4] & 0xff);
        }

        Integer le = null;
        int lc = apdu[4] & 0xff;
        if (lc > 0) {
            // case 3s
            if (apdu.length == 5 + lc) {
                le = null;

            // case 4s
            } else if (apdu.length == 6 + lc) {
                le = Integer.valueOf(apdu[apdu.length - 1] & 0xff);
                
            // error
            } else {
                throw new  SmartcardException(String.format(
                    "Invalid APDU with single byte lc, lc=%d, expected apdu.length of lc + (5 or 6), got %d, apdu: %s",
                    lc, apdu.length, Hex.b2s(apdu)));
            }
            byte[] data = new byte[lc];
            System.arraycopy(apdu, 5, data, 0, data.length);
            return card.transmit(cla, ins, p1, p2, data, le);
        }

        // case 2e
        lc = (apdu[5] & 0xff) << 8 | (apdu[6] & 0xff);
        if (apdu.length == 7) {
            return card.transmit(cla, ins, p1, p2, null, lc);
        
        // case 3e
        } else if (apdu.length == lc + 8) {
            le = null;

        // case 4e
        } else if (apdu.length == lc + 10) {
            le = (apdu[apdu.length - 2] & 0xff) << 8 | (apdu[apdu.length - 1] & 0xff);

        // error
        } else {
            throw new SmartcardException(String.format(
                "Invalid APDU with double byte lc, lc=%d, expected apdu.length of lc + (8 or 10), got %d, apdu: %s",
                lc, apdu.length, Hex.b2s(apdu)));
        }
        byte[] data = new byte[lc];
        java.lang.System.arraycopy(apdu, 7, data, 0, data.length);
        return card.transmit(cla, ins, p1, p2, data, le);
    }
}