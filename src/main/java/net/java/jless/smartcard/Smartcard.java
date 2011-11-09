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

package net.java.jless.smartcard;

public interface Smartcard {
    /**
     * @return IFD name
     */
    String getIFDName();

    /**
     * Transmit APDU and return response
     * @param apdu apdu to send
     * @return response
     * @throws SmartcardException if error
     */
    APDURes transmit(byte[] apdu) throws SmartcardException;

    /**
     * Send hex encoded apdu and return hex encoded response
     * @param hexApdu apdu to send
     * @return response
     * @throws SmartcardException if error
     */
    String transmith(String hexApdu) throws SmartcardException;

    /**
     * Send APDU as parts.
     * @param cla class
     * @param ins instruction
     * @param p1 parameter 1
     * @param p2 parameter 2
     * @param data data
     * @param le length expected
     * @return response
     * @throws SmartcardException if error
     */
    APDURes transmit(int cla, int ins, int p1, int p2, byte[] data, Integer le) throws SmartcardException;

    /**
     * Disconnect from card
     * @param reset if true, reset is done on card
     * @throws SmartcardException
     */
    void disconnect(boolean reset) throws SmartcardException;
}
