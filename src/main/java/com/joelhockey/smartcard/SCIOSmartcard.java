/*
 * Copyright 2009-2011 Joel Hockey (joel.hockey@gmail.com).  All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
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
                log.debug("apdu > (len=" + apdu.length + ") " + Hex.b2s(apdu));
            }
            APDURes res = new APDURes(card.getBasicChannel().transmit(req).getBytes());
            if (debug && log.isDebugEnabled()) {
                long timeTaken = System.currentTimeMillis() - start;
                log.debug("apdu < (len=" + res.getBytes().length + ", time=" + timeTaken + " ms) " + Hex.b2s(res.getBytes()));
            }
            return res;
        } catch (CardException e) {
            throw new SmartcardException(e);
        }
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
        try {
            card.disconnect(reset);
        } catch (CardException e) {
            throw new SmartcardException(e);
        }
    }

    /** {@inheritDoc} */
    public String toString() { return card.toString(); }
}
