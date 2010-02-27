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

import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.joelhockey.codec.Hex;

public class SCIOSmartcard implements Smartcard {
    private static final Log log = LogFactory.getLog(SCIOSmartcard.class);

    private Card card;
    private boolean debug = false;
    
    public SCIOSmartcard(Card card) {
        this.card = card;
    }
    
    public APDURes transmit(byte[] apdu) throws SmartcardException {
        try {
            CommandAPDU req = new CommandAPDU(apdu);
            if (debug && log.isDebugEnabled()) {
                log.debug("apdu > " + Hex.b2s(apdu));
            }
            APDURes res = new APDURes(card.getBasicChannel().transmit(req).getBytes());
            if (debug && log.isDebugEnabled()) {
                log.debug("apdu < " + Hex.b2s(res.getBytes()));
            }
            return res;
        } catch (CardException e) {
            throw new SmartcardException(e);
        }
    }

    public void disconnect(boolean reset) throws SmartcardException {
        try {
            card.disconnect(reset);
        } catch (CardException e) {
            throw new SmartcardException(e);
        }
    }

    /**
     * set debug on or off.
     * @param debug on or off
     */
    public void setDebug(boolean debug) { this.debug = debug; }
}
