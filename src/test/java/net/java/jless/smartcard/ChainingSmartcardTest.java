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

package net.java.jless.smartcard;

import java.util.List;

import net.java.jless.smartcard.ChainingSmartcard;

import junit.framework.TestCase;

/**
 * Test ChainingSmartcard.
 * @author Joel Hockey
 */
public class ChainingSmartcardTest extends TestCase {

    /** Test chaining.  */
    public void testChaining() {
        int maxDataLen = 255;
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
        expected(apdu, maxDataLen, apdu);

        // 2s
        String le = "00";
        apdu = header4 + le;
        expected(apdu, maxDataLen, apdu);

        // 3s, 4s
        for (int i = 1; i < 0x100; i++) {
            String body = Hex.b2s(Buf.random(i));
            String lc = Hex.b2s(new byte[] {(byte) i});
            // 3s
            apdu = header4 + lc + body;
            expected(apdu, maxDataLen, apdu);

            // 4s
            apdu = header4 + lc + body + le;
            expected(apdu, maxDataLen, apdu);
        }

        // 2e
        String extle = "0000";
        expected(header4 + "00" + extle, maxDataLen, header4 + le);

        // 3e, 4e no body
        expected(header4 + "000000", maxDataLen, header4 + "00");
        expected(header4 + "000000" + extle, maxDataLen, header4 + "00" + le);

        // 3e, 4e with body
        chain(10, 255); // test up to 10 chains of 255

        // unusual size maxDataLen
        for (int i = 1; i < 100; i++) {
            chain(5, i);
        }
    }

    private void chain(int maxChainPieces, int maxDataLen) {
        String header4 = "00000000";
        String extle = "0000";
        String body = Hex.b2s(Buf.random(maxChainPieces * maxDataLen));
        int lc = 1;
        for (int chainPieces = 1; chainPieces < maxChainPieces; chainPieces++) {
            int lastPieceStart = (chainPieces - 1) * maxDataLen * 2;
            String[] expectedChain = new String[chainPieces];
            for (int i = 0; i < chainPieces - 1; i++) {
                expectedChain[i] = "10000000" + Hex.b2s(new byte[] {(byte) maxDataLen}) + body.substring(i * maxDataLen * 2, (i + 1) * maxDataLen * 2);
            }
            for (int i = 1; i <= maxDataLen; i++) {
                String bodypart = body.substring(lastPieceStart, lc * 2);
                String extlc = Hex.b2s(new byte[] {0, (byte) (lc >> 8), (byte) lc});

                // 3e
                expectedChain[chainPieces - 1] = header4 + Hex.b2s(new byte[] {(byte) i}) + bodypart;
                String apdu = header4 + extlc + body.substring(0, lc * 2);
                expected(apdu, maxDataLen, expectedChain);

                // 4e
                expectedChain[chainPieces - 1] += extle.substring(2);
                apdu += extle;
                expected(apdu, maxDataLen, expectedChain);

                lc++;
            }
        }
    }

    private void expected(String apduIn, int maxDataLen, String...chain) {
        List<byte[]> actual = ChainingSmartcard.chain(Hex.s2b(apduIn), maxDataLen);
        assertEquals("chain size", chain.length, actual.size());
        for (int i = 0; i < chain.length; i++) {
            assertEquals("piece " + (i + 1) + "\nin: " + apduIn, chain[i], Hex.b2s(actual.get(i)));
        }
    }
}