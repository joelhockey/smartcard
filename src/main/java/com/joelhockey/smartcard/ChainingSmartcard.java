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
import java.util.Collections;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.joelhockey.codec.Buf;
import com.joelhockey.codec.Hex;

public class ChainingSmartcard implements Smartcard {
    private static final Log log = LogFactory.getLog(ChainingSmartcard.class);
    private Smartcard card;

    public ChainingSmartcard(Smartcard card) {
        this.card = card;
    }

    public static APDURes transmitChain(Smartcard card, byte[] apdu) throws SmartcardException {
        List<byte[]> pieces = chain(apdu, 255);

        // log full apdu if chaining
        if (pieces.size() > 1 && log.isDebugEnabled()) {
            log.debug("chaining (" + apdu.length + " bytes, " + pieces.size() + " pieces) > " + Hex.b2s(apdu));
        }

        APDURes res = null;
        for (byte[] piece : pieces) {
            StringBuilder sb = new StringBuilder("apdu (" + piece.length + ") > ");
            Hex.dump(sb, piece, 0, piece.length, "  ", 32);
            log.debug(sb.toString());
            long start = System.nanoTime();
            res = card.transmit(piece);
            long end = System.nanoTime();
            long timeTaken = (end - start) / 1000000;
            sb = new StringBuilder(timeTaken + " ms - apdu (" + res.getBytes().length + ") < ");
            Hex.dump(sb, res.getBytes(), 0, res.getBytes().length, "  ", 32);
            log.debug(sb.toString());
            if (res.getSW() != 0x9000) {
                return res;
            }
        }
        return res;
    }

    /**
     * Split apdu into chain pieces with data size 255 or less.
     * <pre>
     * case 1:  |CLA|INS|P1 |P2 |                                 len = 4
     * case 2s: |CLA|INS|P1 |P2 |LE |                             len = 5
     * case 3s: |CLA|INS|P1 |P2 |LC |...BODY...|                  len = 6..260
     * case 4s: |CLA|INS|P1 |P2 |LC |...BODY...|LE |              len = 7..261
     * case 2e: |CLA|INS|P1 |P2 |00 |LE1|LE2|                     len = 7
     * case 3e: |CLA|INS|P1 |P2 |00 |LC1|LC2|...BODY...|          len = 8..65542
     * case 4e: |CLA|INS|P1 |P2 |00 |LC1|LC2|...BODY...|LE1|LE2|  len =10..65544
     * </pre>
     * @param apdu apdu
     * @param maxDataLen max len of data (usually 255)
     * @return list of chained apdus
     */
    public static List<byte[]> chain(byte[] apdu, int maxDataLen) {
        // shortcut for single apdu (1, 2s, 3s, 4s)
        if (apdu.length <= 6 // 1, 2s, 4s
                || apdu[4] != 0) { // 3s, 4s
            return Collections.singletonList(apdu);
        }

        // apdu is extended (2e, 3e, 4e)
        int offset = 7; // start of body

        // check for 2e
        // we can only use last byte of le
        if (apdu.length == 7) {
            return Collections.singletonList(Buf.cat(Buf.substring(apdu, 0, 4), Buf.substring(apdu, -1, 1)));
        }

        // must be 3e or 4e
        int lc = ((apdu[5] & 0xff) << 8) | (apdu[6] & 0xff);
        boolean leIncluded = apdu.length > 7 + lc;

        // always at least 1 piece
        int chainPieces = lc == 0 ? 1 : (lc + maxDataLen - 1) / maxDataLen;
        int pieceLen = maxDataLen;
        List<byte[]> result = new ArrayList<byte[]>(chainPieces);

        for (int i = 0; i < chainPieces; i++) {
            byte[] apduPart;
            // all except last
            if (i < chainPieces - 1) {
                apduPart = new byte[5 + maxDataLen];
                apduPart[0] = (byte) (apdu[0] | 0x10);
            // last
            } else {
                pieceLen = lc - (maxDataLen * (chainPieces - 1));
                apduPart = new byte[5 + pieceLen + (leIncluded ? 1 : 0)];
                apduPart[0] = apdu[0];
                apduPart[apduPart.length - 1] = apdu[apdu.length - 1]; // takes care of le
            }
            apduPart[1] = apdu[1];
            apduPart[2] = apdu[2];
            apduPart[3] = apdu[3];
            apduPart[4] = (byte) pieceLen;
            System.arraycopy(apdu, offset, apduPart, 5, pieceLen);
            offset += maxDataLen;
            result.add(apduPart);
        }
        return result;
    }

    /** {@inheritDoc} */
    public String getIFDName() { return card.getIFDName(); }

    /** {@inheritDoc} */
    public APDURes transmit(byte[] apdu) throws SmartcardException {
        return transmitChain(card, apdu);
    }

    /** {@inheritDoc} */
    public String transmith(String hexApdu) throws SmartcardException {
        return transmit(Hex.s2b(hexApdu)).toString();
    }

    /** {@inheritDoc} */
    public APDURes transmit(int cla, int ins, int p1, int p2, byte[] data, Integer le) throws SmartcardException {
        return transmit(SmartcardUtil.formatAPDU(cla, ins, p1, p2, data, le));
    }

    /** {@inheritDoc} */
    public void disconnect(boolean reset) throws SmartcardException {
        card.disconnect(reset);
    }
}
