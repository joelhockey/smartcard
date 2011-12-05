/*
 * Copyright 2008-2011 Joel Hockey (joel.hockey@gmail.com).  All rights reserved.
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

import java.security.SecureRandom;



/**
 * Byte array utils.
 * @author Joel Hockey
 */
public class Buf {

    /**
     * concatenate bufs.
     * @param bufs parts to concatenate
     * @return concatenated
     */
    public static byte[] cat(byte[]... bufs) {
        if (bufs == null) {
            return null;
        }
        int l = 0;
        for (int i = 0; i < bufs.length; i++) {
            l += bufs[i] == null ? 0 : bufs[i].length;
        }

        byte[] result = new byte[l];
        cat(result, 0, bufs);
        return result;
    }

    /**
     * cat into dest starting at start.
     * @param dest destination
     * @param start position to start writing
     * @param bufs parts to concatenate
     */
    public static void cat(byte[] dest, int start, byte[]... bufs) {
        if (bufs == null) {
            return;
        }
        for (int i = 0; i < bufs.length; i++) {
            if (bufs[i] != null) {
                System.arraycopy(bufs[i], 0, dest, start, bufs[i].length);
                start += bufs[i].length;
            }
        }
    }

    /**
     * Substring of buf.  Allows negative indexing as per python.
     * If range of substring outside range of buf, then result is zero-padded.
     * Result will be left justified if start is positive,
     * right-justified if start is negative.
     * @param src src to get sub buf
     * @param start index to start
     * @param len index to end
     * @return buf len (end - start) containing src
     */
    public static byte[] substring(byte[] src, int start, int len) {
        if (len < 0) {
            throw new IllegalArgumentException("len cannot be negative, got: " + len);
        }

        if (src == null) { src = new byte[0]; }
        if (src != null && start == 0 && len == src.length) {
            return src;
        }

        // result is src
        if (len == src.length && (start == 0 || start == -src.length)) {
            return src;
        }

        byte[] result = new byte[len];
        // left-justified
        if (start >= 0 && start < src.length) {
            int tocopy = Math.min(len, src.length - start);
            System.arraycopy(src, start, result, 0, tocopy);

        // right-justified
        } else if (start < 0 && start + src.length + len > 0) {
            start += src.length;
            int tocopy = start < 0 ?
                    Math.min(len + start, src.length)
                    : Math.min(len, src.length - start);
            System.arraycopy(src, Math.max(0, start), result, len - tocopy, tocopy);
        }

        return result;
    }

    /**
     * Substring of buf from start to end
     * @param src src to get sub buf
     * @param start index to start
     * @return buf len (end - start) containing src
     */
    public static byte[] substring(byte[] src, int start) {
        return substring(src, start, src.length - start);
    }

    /**
     * Return random bytes
     * @param numBytes number of bytes
     * @return random bytes
     */
    public static byte[] random(int numBytes) {
        byte[] buf = new byte[numBytes];
        new SecureRandom().nextBytes(buf);
        return buf;
    }

    /**
     * Convert short array into byte array with shorts as 16-bit big-endian values.
     * @param sa short array
     * @return shorts as byte array as 16-bit big-endian values
     */
    public static byte[] s2b(short... sa) {
        if (sa == null || sa.length == 0) {
            return new byte[0];
        }

        byte[] result = new byte[sa.length * 2];
        // start at rhs and work back
        int j = result.length - 1;
        for (int i = sa.length - 1; i >= 0; i--) {
            int val = sa[i];
            result[j--] = (byte) val;
            val >>= 8;
            result[j--] = (byte) val;
        }
        return result;
    }

    /**
     * Convert int array into byte array with ints as 32-bit big-endian values.
     * @param ia int array
     * @return ints as byte array as 32-bit big-endian values
     */
    public static byte[] i2b(int... ia) {
        if (ia == null || ia.length == 0) {
            return new byte[0];
        }

        byte[] result = new byte[ia.length * 4];
        // start at rhs and work back
        int j = result.length - 1;
        for (int i = ia.length - 1; i >= 0; i--) {
            int val = ia[i];
            result[j--] = (byte) val;
            val >>= 8;
            result[j--] = (byte) val;
            val >>= 8;
            result[j--] = (byte) val;
            val >>= 8;
            result[j--] = (byte) val;
        }
        return result;
    }

}
