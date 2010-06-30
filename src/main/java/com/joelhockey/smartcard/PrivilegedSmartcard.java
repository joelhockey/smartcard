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
    public APDURes transmith(String hexApdu) throws SmartcardException {
        return transmit(Hex.s2b(hexApdu));
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
