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

import java.util.Arrays;

public class APDURes {
    private int sw;
    private int sw1;
    private int sw2;
    private byte[] apdu;

    /**
     * Constructor [data || sw1 || sw2].
     * @param apdu apdu
     */
    public APDURes(byte[] apdu) {
        this.apdu = apdu;
        sw1 = apdu[apdu.length - 2] & 0xff;
        sw2 = apdu[apdu.length - 1] & 0xff;
        sw = (sw1 << 8) | sw2;
    }

    /**
     * Constructor taking hex string for [data || sw1 || sw2].
     * @param hexApdu hex apdu
     */
    public APDURes(String hexApdu) {
        this(Hex.s2b(hexApdu));
    }

    /** @return status words. */
    public int getSW() { return sw; }
    /** @return sw1. */
    public int getSW1() { return sw1; }
    /** @return sw2. */
    public int getSW2() { return sw2; }

    /** @return data. */
    public byte[] getData() { return Arrays.copyOf(apdu, apdu.length - 2); }

    /** @return full apdu bytes (data and sw). */
    public byte[] getBytes() { return apdu; }

    /** @return hex apdu (data and sw). */
    public String toString() { return Hex.b2s(apdu); }

}
