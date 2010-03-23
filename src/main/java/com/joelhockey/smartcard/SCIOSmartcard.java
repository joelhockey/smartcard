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
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.joelhockey.codec.Hex;

/**
 * Implements {@link Smartcard} interface using
 * {@link javax.smartcardio.Card}.
 * @author Joel Hockey
 */
public class SCIOSmartcard implements Smartcard {
    private static final Log log = LogFactory.getLog(SCIOSmartcard.class);

    private String ifdName;
    private Card card;
    private boolean debug = false;

    /**
     * Constructor taking {@link javax.smartcardio.Card}.
     * @param card {@link javax.smartcardio.Card}
     */
    public SCIOSmartcard(Card card) {
        this(card, null);
    }

    /**
     * Constructor taking {@link javax.smartcardio.Card}.
     * @param card {@link javax.smartcardio.Card}
     * @param ifdName IFD name
     */
    public SCIOSmartcard(Card card, String ifdName) {
        this.card = card;
        this.ifdName = ifdName;
    }

    /**
     * Constructor taking {@link javax.smartcardio.CardTerminal }.
     * Calls {@link CardTerminal#connect(String)} with <code>"*"</code>.
     * @param terminal card terminal
     * @throws CardException if error connecting
     */
    public SCIOSmartcard(CardTerminal terminal) throws CardException {
        this(terminal.connect("*"), terminal.getName());
    }

    /**
     * Return {@link javax.smartcardio.Card}.
     * @return card
     */
    public Card getCard() { return card; }

    /**
     * set debug on or off.
     * @param debug on or off
     */
    public void setDebug(boolean debug) { this.debug = debug; }

    /** {@inheritDoc} */
    public String getIFDName() { return ifdName; }

    /** {@inheritDoc} */
    public APDURes transmit(byte[] apdu) throws SmartcardException {
        try {
            CommandAPDU req = new CommandAPDU(apdu);
            long start = 0;
            if (debug && log.isDebugEnabled()) {
                start = System.currentTimeMillis();
                log.debug("apdu (" + apdu.length + ") > " + Hex.b2s(apdu));
            }
            APDURes res = new APDURes(card.getBasicChannel().transmit(req).getBytes());
            if (debug && log.isDebugEnabled()) {
                long timeTaken = System.currentTimeMillis() - start;
                log.debug(timeTaken + " ms - apdu (" + res.getBytes().length + ") < " + Hex.b2s(res.getBytes()));
            }
            return res;
        } catch (CardException e) {
            throw new SmartcardException(e);
        }
    }

    /** {@inheritDoc} */
    public APDURes transmit(int cla, int ins, int p1, int p2, byte[] data, Integer le) throws SmartcardException {
        return transmit(SmartcardUtil.formatAPDU(cla, ins, p1, p2, data, le));
    }

    /** {@inheritDoc} */
    public void disconnect(boolean reset) throws SmartcardException {
        try {
            card.disconnect(reset);
        } catch (CardException e) {
            throw new SmartcardException(e);
        }
    }
}
