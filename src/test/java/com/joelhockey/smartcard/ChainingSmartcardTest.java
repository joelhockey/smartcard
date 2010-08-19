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

import java.util.List;

import junit.framework.TestCase;

import com.joelhockey.codec.Buf;
import com.joelhockey.codec.Hex;

/**
 * Test ChainingSmartcard.
 * @author Joel Hockey
 */
public class ChainingSmartcardTest extends TestCase {

    /** Test chaining.  */
    public void testChaining() {
        /*
         * case 1:  |CLA|INS|P1 |P2 |                                 len = 4
         * case 2s: |CLA|INS|P1 |P2 |LE |                             len = 5
         * case 3s: |CLA|INS|P1 |P2 |LC |...BODY...|                  len = 6..260
         * case 4s: |CLA|INS|P1 |P2 |LC |...BODY...|LE |              len = 7..261
         * case 2e: |CLA|INS|P1 |P2 |00 |LE1|LE2|                     len = 7
         * case 3e: |CLA|INS|P1 |P2 |00 |LC1|LC2|...BODY...|          len = 8..65542
         * case 4e: |CLA|INS|P1 |P2 |00 |LC1|LC2|...BODY...|LE1|LE2|  len =10..65544
         */
        String header4 = "00000000"; // cla|ins|p1|p2

        // 1
        String apdu = header4;
        expected(apdu, apdu);

        // 2s
        String le = "00";
        apdu = header4 + le;
        expected(apdu, apdu);

        // 3s, 4s
        for (int i = 1; i < 0x100; i++) {
            String body = Hex.b2s(Buf.random(i));
            String lc = Hex.b2s(new byte[] {(byte) i});
            // 3s
            apdu = header4 + lc + body;
            expected(apdu, apdu);

            // 4s
            apdu = header4 + lc + body + le;
            expected(apdu, apdu);
        }

        // 2e
        String extle = "0000";
        expected(header4 + "00" + extle, header4 + le);

        // 3e, 4e no body
        expected(header4 + "000000", header4 + "00");
        expected(header4 + "000000" + extle, header4 + "00" + le);

        // 3e, 4e with body
        int maxChainPieces = 10;
        String body = Hex.b2s(Buf.random(maxChainPieces * 255));
        int lc = 1;
        for (int chainPieces = 1; chainPieces < maxChainPieces; chainPieces++) {
            int lastPieceStart = (chainPieces - 1) * 255 * 2;
            String[] expectedChain = new String[chainPieces];
            for (int i = 0; i < chainPieces - 1; i++) {
                expectedChain[i] = "10000000ff" + body.substring(i * 255 * 2, (i + 1) * 255 * 2);
            }
            for (int i = 1; i < 0x100; i++) {
                String bodypart = body.substring(lastPieceStart, lc * 2);
                String extlc = Hex.b2s(new byte[] {0, (byte) (lc >> 8), (byte) lc});

                // 3e
                expectedChain[chainPieces - 1] = header4 + Hex.b2s(new byte[] {(byte) i}) + bodypart;
                apdu = header4 + extlc + body.substring(0, lc * 2);
                expected(apdu, expectedChain);

                // 4e
                expectedChain[chainPieces - 1] += extle.substring(2);
                apdu += extle;
                expected(apdu, expectedChain);

                lc++;
            }
        }
    }

    private void expected(String apduIn, String...chain) {
        List<byte[]> actual = ChainingSmartcard.chain(Hex.s2b(apduIn));
        assertEquals("chain size", chain.length, actual.size());
        for (int i = 0; i < chain.length; i++) {
            assertEquals("piece " + (i + 1) + "\nin: " + apduIn, chain[i], Hex.b2s(actual.get(i)));
        }
    }
}