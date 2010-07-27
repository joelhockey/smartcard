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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.joelhockey.codec.Hex;

public class ChainingSmartcard implements Smartcard {
    private static final Log log = LogFactory.getLog(ChainingSmartcard.class);
    private Smartcard card;

    public ChainingSmartcard(Smartcard card) {
        this.card = card;
    }

    public static APDURes transmitChain(Smartcard card, byte[] apdu) throws SmartcardException {
        int maxDataLen = 255;

        // shortcut for single apdu
        if ((apdu[4] == 0 && apdu.length < 7) || (apdu[4] != 0  && apdu.length < (5 + maxDataLen + 1))) {
            return transmitPiece(card, apdu);
        }

        // calculate lc allowing extended length
        int lc = apdu[4] & 0xff;
        boolean leIncluded = apdu.length > 5 + lc;
        int offset = 5;
        if (lc == 0 && apdu.length > 6) {
            lc = ((apdu[5] & 0xff) << 8) | (apdu[6] & 0xff);
            leIncluded = apdu.length > 7 + lc;
            offset += 2;
        }
        int chainPieces = (lc + maxDataLen - 1) / maxDataLen;
        int pieceLen = maxDataLen;

        // log full apdu if chaining
        if (chainPieces > 1 && log.isDebugEnabled()) {
            log.debug("chaining (" + apdu.length + " bytes, " + chainPieces + " pieces) > " + Hex.b2s(apdu));
        }

        APDURes res = null;
        for (int i = 0; i < chainPieces; i++) {
            byte[] apduPart;
            // all except last
            if (i < chainPieces - 1) {
                apduPart = new byte[5 + maxDataLen];
                apduPart[0] = (byte) (apdu[0] | 0x10);
            // last
            } else {
                pieceLen = lc - (255 * (chainPieces - 1));
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
            res = transmitPiece(card, apduPart);
            if (res.getSW() != 0x9000) {
                return res;
            }
        }
        return res;
    }

    private static APDURes transmitPiece(Smartcard card, byte[] apdu) throws SmartcardException {
        StringBuilder sb = new StringBuilder("apdu (" + apdu.length + ") > ");
        Hex.dump(sb, apdu, 0, apdu.length, "  ", 32);
        log.debug(sb.toString());
        long start = System.nanoTime();
        APDURes res = card.transmit(apdu);
        long end = System.nanoTime();
        long timeTaken = (end - start) / 1000000;
        sb = new StringBuilder(timeTaken + " ms - apdu (" + res.getBytes().length + ") < ");
        Hex.dump(sb, res.getBytes(), 0, res.getBytes().length, "  ", 32);
        log.debug(sb.toString());
        return res;
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
