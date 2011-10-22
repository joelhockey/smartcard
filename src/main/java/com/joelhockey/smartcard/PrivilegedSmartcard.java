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

import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import com.joelhockey.codec.Hex;

/**
 * Executes all methods using {@link AccessController#doPrivileged(java.security.PrivilegedAction)}. This allows
 * Javascript to call Applet and use the signed applets security context.
 * @author Joel Hockey
 */
public class PrivilegedSmartcard implements Smartcard {
    private Smartcard card;

    /**
     * Create privileged smartcard.
     * @param card base card
     */
    public PrivilegedSmartcard(Smartcard card) {
        this.card = card;
    }

    /** {@inheritDoc}} */
    public void disconnect(final boolean reset) throws SmartcardException {
        try {
            AccessController.doPrivileged(new PrivilegedExceptionAction() {
                public Object run() throws SmartcardException {
                    card.disconnect(reset);
                    return null;
                }
            });
        } catch (PrivilegedActionException pae) {
            throw (SmartcardException) pae.getException();
        }
    }

    /** {@inheritDoc}} */
    public String getIFDName() {
        return card.getIFDName();
    }

    /** {@inheritDoc}} */
    public APDURes transmit(final byte[] apdu) throws SmartcardException {
        try {
            return AccessController.doPrivileged(new PrivilegedExceptionAction<APDURes>() {
                public APDURes run() throws SmartcardException {
                    return card.transmit(apdu);
                }
            });
        } catch (PrivilegedActionException pae) {
            throw (SmartcardException) pae.getException();
        }
    }

    /** {@inheritDoc} */
    public String transmith(String hexApdu) throws SmartcardException {
        return transmit(Hex.s2b(hexApdu)).toString();
    }

    /** {@inheritDoc}} */
    public APDURes transmit(final int cla, final int ins, final int p1, final int p2, final byte[] data, final Integer le)
            throws SmartcardException {

        try {
            return AccessController.doPrivileged(new PrivilegedExceptionAction<APDURes>() {
                public APDURes run() throws SmartcardException {
                    return card.transmit(cla, ins, p1, p2, data, le);
                }
            });
        } catch (PrivilegedActionException pae) {
            throw (SmartcardException) pae.getException();
        }
    }
}
