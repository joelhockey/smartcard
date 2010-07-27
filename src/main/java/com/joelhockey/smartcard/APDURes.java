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

import java.util.Arrays;

import com.joelhockey.codec.Hex;

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
