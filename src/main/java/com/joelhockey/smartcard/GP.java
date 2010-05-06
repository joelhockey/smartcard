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

import static java.lang.String.format;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.TerminalFactory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.joelhockey.codec.Buf;
import com.joelhockey.codec.Hex;
import com.joelhockey.codec.TLV;
import com.joelhockey.smartcard.GetStatusResult.AppRecord;
import com.joelhockey.smartcard.GetStatusResult.LoadFileRecord;

/**
 * Global Platform commands as per v2.1.1 spec available at
 * <a href="http://globalplatform.org/">http://globalplatform.org</a>
 *
 * @author Joel Hockey
 */
public class GP {
    private static final Log log = LogFactory.getLog(GP.class);

    /** Gemalto Card Mgr AID 'A000000018434D00'. */
    public static final String GEMALTO_CARD_MGR = "A000000018434D00";
    /** Max APDU Data len '255'. */
    public static final int MAX_APDU_LEN_STANDARD = 255;

    private Smartcard smartcard;
    private String currentSelected;
    private boolean useMAC = false;
    private boolean useEncrypt = false;
    private int maxDataLen = MAX_APDU_LEN_STANDARD;
    private int currentKeyVersion = -1;

    private byte[] macIV = new byte[8];

    // keys and ciphers
    private byte[] staticENC;
    private byte[] staticMAC;
    private byte[] staticDEK;
    private byte[] sessionCMAC;
    private byte[] sessionSENC;
    private byte[] sessionDEK;
    private Cipher des3ecb;
    private Cipher des3cbc;
    private Cipher des1cbc;

    {
        try {
            des3ecb = Cipher.getInstance("DESede/ECB/NoPadding");
            des3cbc = Cipher.getInstance("DESede/CBC/NoPadding");
            des1cbc = Cipher.getInstance("DES/CBC/NoPadding");
        } catch (Exception e) {
            log.warn("Error creating DES cipher objects, will continue", e);
        }

    }

    /**
     * Constructor fails if not exactly 1 card present.
     * @throws CardException if error
     * @throws GeneralSecurityException
     */
    public GP() throws CardException {
        List<CardTerminal> cards = TerminalFactory.getDefault().terminals().list(CardTerminals.State.CARD_PRESENT);
        if (cards.size() != 1) {
            throw new IllegalStateException("Didn't find exactly 1 card, found: " + cards.size());
        }
        log.debug("new GP detected single card: " + cards.get(0));
        this.smartcard = new SCIOSmartcard(cards.get(0).connect("*"));
    }

    /**
     * Constructor using Smartcard interface.
     * @param card card to use
     */
    public GP(Smartcard card) {
        log.debug("new GP with GP card interface: " + card);
        this.smartcard = card;
    }

    /**
     * Create GP from javax.smartcardio.Card.
     * @param card javax.smartcardio.Card object
     * @return GP
     */
    public static GP newSCIO(Card card) {
        return new GP(new SCIOSmartcard(card));
    }

    /** @return card */
    public Smartcard getSmartcard() { return smartcard; }

    /** @return current selected app (upper case hex aid) */
    public String getCurrentSelected() { return currentSelected; }

    /**
     * Must establish SCP02 session before calling this.
     * Current Key Version is detected during SCP02 INITIALIZE UPDATE.
     * @return current key version, or -1 if current version not known
     */
    public int getCurrentKeyVersion() { return currentKeyVersion; }

    /**
     * Terminate SCP02 session, but do not disconnect from card.
     * @see #close()
     */
    public void terminateSCP02() {
        useEncrypt = false;
        useMAC = false;
        macIV = new byte[8];
    }

    /**
     * Close any card connections (terminates any SCP02 sessions).
     * @throws SmartcardException if card error
     * @see #terminateSCP02()
     */
    public void close() throws SmartcardException {
        terminateSCP02();
        smartcard.disconnect(true);
    }

    /**
     * Executes Initialize-Update command until card returns error (not 0x9000).
     * WARNING!  Gemalto simulator doesn't ever seem to lock which turns this method
     * into an infinite loop.
     * WARNING!  This will lock your cards so that you cannot open a secure channel again EVER.
     * @throws SmartcardException if card error
     * @throws GeneralSecurityException if crypto error
     */
    public void lockCard() throws SmartcardException, GeneralSecurityException {
        log.debug("locking card");
        // select gemalto card manager
        select(GEMALTO_CARD_MGR);

        int i = 0;
        APDURes res;
        do {
            // initialize-update with 8 bytes
            log.debug("sending init-update " + ++i);
            byte[] hostChallenge = new byte[8];
            res = transmit(0x80, 0x50, 0x00, 0x00, hostChallenge, 0);
        } while (res.getSW() == 0x9000);
        log.debug("card now locked after " + (i - 1));
    }

    /**
     * Global Platform DELETE.  GP v2.1.1 9.2.
     * Silently ignores any errors.
     * @param aid Application ID
     * @throws SmartcardException if card error
     * @throws GeneralSecurityException if crypto error
     */
    public void delete(String aid) throws SmartcardException, GeneralSecurityException {
        log.debug("delete " + aid);
        APDURes res = transmit(0x80, 0xE4, 0, 0, TLV.encode(0x40, 0x0f, Hex.s2b(aid)), null);
        if (res.getSW() != 0x9000) {
            log.warn("Data (aid=" + aid + ") not found to delete, will continue");
        }
    }

    /**
     * Global Platform DELETE Key. GP v2.1.1 9.2.2.3
     * @param id key id
     * @param version key version
     * @throws SmartcardException if card error
     * @throws GeneralSecurityException if crypto error
     */
    public void deleteKey(int id, int version) throws SmartcardException, GeneralSecurityException {
        log.debug("delete key id: " + id + ", version: " + version);
        APDURes res = transmit(0x80, 0xE4, 0, 0,
                new byte[] {(byte) 0xd0, 1, (byte) id, (byte) 0xd2, 1, (byte) version}, 0);
        if (res.getSW() != 0x9000) {
               log.warn("Key (id=" + id + ", version=" + version + ") not found to delete, will continue");
        }
    }

    /**
     * Global Platform GET DATA GP v2.1.1 9.3.
     * @param p1p2 combination of p1 and p2.  E.g. 0x00cf
     * @return data
     * @throws SmartcardException if card error
     * @throws GeneralSecurityException if crypto error
     */
    public byte[] getData(int p1p2) throws SmartcardException, GeneralSecurityException {
        log.debug(format("get-data 0x%04x", p1p2));
        APDURes res = transmit(0x80, 0xCA, p1p2 >> 8, p1p2 & 0xff, null, 0);
        if (res.getSW() != 0x9000) {
            throw new SmartcardException(format("get-data 0x%04x, SW: %x", p1p2, res.getSW()));
        }
        return res.getData();
    }

    /**
     * Global Platform GET DATA (Key Information) GP v2.1.1 9.3.3
     * @return list of &lt;keyId>'/'&lt;keyVersion> strings
     * @throws SmartcardException if card error
     * @throws GeneralSecurityException if crypto error
     */
    public List<String> getKeyInfo() throws SmartcardException, GeneralSecurityException {
        List<String> result = new ArrayList<String>();
        for (TLV set : new TLV(getData(0xe0)).split()) {
            result.add(set.getv()[0] + "/" + set.getv()[1]);
        }
        return result;
    }

    /**
     * Global Platform GET STATUS GP v2.1.1 9.4.
     * @return status of Card manager, Applications, and Executable load file.  Result object
     * has a formatted toString method.
     * @throws SmartcardException if card error
     * @throws GeneralSecurityException if crypto error
     */
    public GetStatusResult getStatus() throws SmartcardException, GeneralSecurityException {
        log.debug("get-status");
        GetStatusResult result = new GetStatusResult();

        // get-status p1=0x80 - Issuer Security domain only
        APDURes res = transmit(0x80, 0xF2, 0x80, 0x00, Hex.s2b("4f00"), 0);
        if (res.getSW() != 0x9000) {
            throw new SmartcardException("get-status (Issuer Security Domain) SW: " + Integer.toHexString(res.getSW()));
        }
        byte[] apdu = res.getBytes();

        result.isd.aid = new byte[apdu[0] & 0xff];
        System.arraycopy(apdu, 1, result.isd.aid, 0, result.isd.aid.length);
        result.isd.lifeCycleState = apdu[result.isd.aid.length + 1];
        result.isd.privs = apdu[result.isd.aid.length + 2];

        // get-status p1=0x40 - Applications and Security domains only
        res = transmit(0x80, 0xF2, 0x40, 0x00, Hex.s2b("4f00"), 0);
        // allow sw=0x6a88 (no data)
        if (res.getSW() != 0x9000 && res.getSW() != 0x6a88) {
            throw new SmartcardException("get-status (Applications and Security domains) SW: " + Integer.toHexString(res.getSW()));
        }
        apdu = res.getBytes();
        int i = 0;
        while (i < apdu.length - 2) { // ignore SW at end
            AppRecord rec = new AppRecord();
            rec.aid = new byte[apdu[i] & 0xff];
            System.arraycopy(apdu, i + 1, rec.aid, 0, rec.aid.length);
            i += rec.aid.length + 1;
            rec.lifeCycleState = apdu[i++] & 0xff;
            rec.privs = apdu[i++] & 0xff;
            result.apps.add(rec);
        }

        // get-status p1=0x10 - Executable Load Files and their Executable Modules only
        res = transmit(0x80, 0xF2, 0x10, 0x00, Hex.s2b("4f00"), 0);
        if (res.getSW() != 0x9000 && res.getSW() != 0x6310) {
            throw new SmartcardException(format("get-status (Load Files and Modules only) SW: 0x%04x", res.getSW()));
        }
        apdu = res.getBytes();
        i = 0;
        while (i < apdu.length - 2) { // ignore SW at end
            LoadFileRecord rec = new LoadFileRecord();
            rec.aid = new byte[apdu[i++] & 0xff];
            System.arraycopy(apdu, i, rec.aid, 0, rec.aid.length);
            i += rec.aid.length;
            rec.lifeCycleState = apdu[i++] & 0xff;
            rec.privs = apdu[i++] & 0xff;
            int numModules = apdu[i++] & 0xff;
            for (int j = 0; j < numModules; j++) {
                byte[] aid = new byte[apdu[i++] & 0xff];
                System.arraycopy(apdu, i, aid, 0, aid.length);
                rec.moduleAids.add(aid);
                i += aid.length;
            }
            result.loadFiles.add(rec);
        }
        log.debug("Card Status\n" + result);
        return result;
    }

    /**
     * Global Platform INSTALL (for Load) GP v2.1.1 9.5.
     * @param loadFileAid Load file AID
     * @param securityDomainAid Security Domain AID
     * @throws SmartcardException if card error
     * @throws GeneralSecurityException if crypto error
     */
    public void installForLoad(String loadFileAid, String securityDomainAid) throws SmartcardException, GeneralSecurityException {
        log.debug("installForLoad loadFileAid: " + loadFileAid + ", securityDomainAid: " + securityDomainAid);
        byte[] pkg = Hex.s2b(loadFileAid);
        byte[] cardMgr = Hex.s2b(securityDomainAid);

        byte[] data = new byte[5 + pkg.length + cardMgr.length];
        data[0] = (byte) pkg.length;
        System.arraycopy(pkg, 0, data, 1, pkg.length);
        data[pkg.length + 1] = (byte) cardMgr.length;
        System.arraycopy(cardMgr, 0, data, pkg.length + 2, cardMgr.length);
        APDURes res = transmit(0x80, 0xE6, 0x02, 0 , data, null);
        if (res.getSW() != 0x9000) {
            throw new SmartcardException(format("install (for Load) loadFileAID: %s, securityDomainAid: %s, SW: 0x%04x",
                loadFileAid, securityDomainAid, res.getSW()));
        }
    }

    /**
     * Global Platform INSTALL (for Install) GP v2.1.1 9.5.
     * @param loadFileAid Load file AID
     * @param moduleAid Module AID
     * @param applicationAid Instance AID
     * @param priv App privs
     * @param installParams Hex encoded install params
     * @throws SmartcardException if card error
     * @throws GeneralSecurityException if crypto error
     */
    public void installForInstall(String loadFileAid, String moduleAid, String applicationAid, int priv, String installParams)
        throws SmartcardException, GeneralSecurityException {

        log.debug(format(
                "installForInstall loadFileAid: %s, moduleAid: %s, applicationAid: %s priv: 0x%02x, installParams: %s",
                loadFileAid, moduleAid, applicationAid, priv, installParams));

        byte[] lfaid = Hex.s2b(loadFileAid);
        byte[] modaid = Hex.s2b(moduleAid);
        byte[] appaid = Hex.s2b(applicationAid);
        byte[] instparam = Hex.s2b(installParams);

        int offset = 0;
        byte[] data = new byte[9 + lfaid.length + modaid.length + appaid.length + instparam.length];
        data[offset++] = (byte) lfaid.length; // lfaid len
        System.arraycopy(lfaid, 0, data, offset, lfaid.length); // lfaid
        offset += lfaid.length;
        data[offset++] = (byte) modaid.length; // modaid len
        System.arraycopy(modaid, 0, data, offset, modaid.length); // modaid
        offset += modaid.length;
        data[offset++] = (byte) appaid.length; // appaid len
        System.arraycopy(appaid, 0, data, offset, appaid.length); // appaid
        offset += appaid.length;
        data[offset++] = 0x01; // app priv len
        data[offset++] = (byte) priv; // app priv
        data[offset++] = (byte) (instparam.length + 2); // install param len
        data[offset++] = (byte) 0xC9; // tlv tag for install param
        data[offset++] = (byte) (instparam.length); // tlv len for install param
        System.arraycopy(instparam, 0, data, offset, instparam.length);
        offset += instparam.length;
        data[offset++] = 0; // inst token len

        APDURes res = transmit(0x80, 0xE6, 0x0C, 0, data, null);
        if (res.getSW() != 0x9000) {
            throw new SmartcardException(format(
                "install (for install) loadFileAid: %s, moduleAid: %s, applicationAid: %s, priv: 0x%02x, SW: 0x%04x",
                loadFileAid, moduleAid, applicationAid,  priv, res.getSW()));
        }
    }

    /**
     * Global Platform LOAD GP v2.1.1 9.6.
     * @param file name of CAP file readable through current classloader
     * @throws SmartcardException if card error
     * @throws GeneralSecurityException if crytpo error
     * @throws IOException if error reading file
     */
    public void load(String file) throws SmartcardException, GeneralSecurityException, IOException {
        log.debug("load " + file);
        Map<String, ByteArrayOutputStream> parts = new HashMap<String, ByteArrayOutputStream>();
        InputStream ins = GP.class.getResourceAsStream(file);
        if (ins == null) {
            throw new IOException("Could not open resource as stream: [" + file + "].  Ensure it is on the java classpath");
        }
        ZipInputStream zis = new ZipInputStream(ins);
        byte[] buf = new byte[4096];
        while (true) {
            ZipEntry entry = zis.getNextEntry();
            if (entry == null) {
                break;
            }
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            String name = entry.getName().substring(entry.getName().lastIndexOf('/') + 1).toUpperCase();
            parts.put(name, baos);
            for (int len = 0; (len = zis.read(buf)) != -1; ) {
                baos.write(buf, 0, len);
            }
        }
        zis.close();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Set<String> optional = new HashSet<String>(Arrays.asList("APPLET.CAP EXPORT.CAP".split(" ")));
        for (String name : ("HEADER.CAP DIRECTORY.CAP IMPORT.CAP APPLET.CAP CLASS.CAP METHOD.CAP "
                + "STATICFIELD.CAP EXPORT.CAP CONSTANTPOOL.CAP REFLOCATION.CAP").split(" ")) {
            ByteArrayOutputStream b = parts.get(name);
            if (b == null) {
                if (optional.contains(name)) {
                    continue;
                } else {
                    throw new IOException("Could not find " + name + " in cap file " + file);
                }
            }
            baos.write(b.toByteArray());
        }

        buf = baos.toByteArray();
        baos.reset();
        baos.write((byte) 0xc4);
        baos.write(TLV.encode_l(buf.length));
        baos.write(buf);
        buf = baos.toByteArray();
        int c = (buf.length + maxDataLen - 1) / maxDataLen;
        int start = 0;
        for (int i = 0; i < c; i++) {
            int p1 = 0x00;
            int end = start + maxDataLen;
            if (i == c - 1) { // last apdu
                end = buf.length;
                p1 = 0x80;
            }
            byte[] data = new byte[end - start];
            System.arraycopy(buf, start, data, 0, data.length);
            start += data.length;
            APDURes res = transmit(0x80, 0xE8, p1, i, data, null);
            if (res.getSW() != 0x9000) {
                throw new SmartcardException("load " + file + " SW: " + Integer.toHexString(res.getSW()));
            }
        }
    }

    /**
     * Global Platform PUT KEY GP v2.1.1 9.8.
     * Replace key ID 1.  Derives ENC, MAC, and DEK keys from masterKey, iin, and cin using
     * EMV key derivation.  KEYDATA is calculated as:
     * <pre>0x00000000 || [last 2 bytes of iin] || [last 4 bytes of CIN]</pre>
     * @param currentKeyVersion current version of key
     * @param newKeyVersion new version of key
     * @param masterKey hex value of key
     * @param iin hex iin
     * @param cin hex cin
     * @throws SmartcardException if smartcard error
     * @throws GeneralSecurityException if crypto error
     */
    public void putKeyDeriveFromMasterIinCin(int currentKeyVersion, int newKeyVersion, String masterKey, String iin, String cin)
        throws SmartcardException, GeneralSecurityException  {

        log.debug("put-key iin: " + iin + " , cin: " + cin);

        // keydata (10 bytes) will be 0x00000000 || [last 2 bytes of iin] || [last 4 bytes of CIN]
        byte[] keydata = Buf.cat(Buf.substring(Hex.s2b(iin), -2, 6), Buf.substring(Hex.s2b(cin), -4, 4));

        putKeyDeriveFromMasterKeydata(currentKeyVersion, newKeyVersion, masterKey, keydata);
    }

    /**
     * Global Platform PUT KEY GP v2.1.1 9.8.
     * Replace key ID 1.  Derived ENC, MAC and DEK keys from masterKey and keydata using EMV key derivation.
     * @param currentKeyVersion current version of key
     * @param newKeyVersion new version of key
     * @param masterKey In software mode, hex value of key, in HSM mode, label of key
     * @param keydata 10 byte key data as defined in EMV CPS v1.1
     * @throws SmartcardException if smartcard error
     * @throws GeneralSecurityException if crypto error
     */
    public void putKeyDeriveFromMasterKeydata(int currentKeyVersion, int newKeyVersion, String masterKey, byte[] keydata)
        throws SmartcardException, GeneralSecurityException {

        log.debug("put-key currentKeyVersion: " + currentKeyVersion + ", newKeyVersion: " + newKeyVersion
                + ", masterKey: " + masterKey + ", keydata: " + Hex.b2s(keydata));

        if (keydata.length != 10) {
            throw new IllegalArgumentException("KEYDATA must be 10 bytes, got: "
                + keydata.length + ", [" + Hex.b2s(keydata) + "]");
        }

        byte[] masterKeyBuf = Hex.s2b(masterKey);
        if (masterKeyBuf.length != 16) {
            throw new IllegalArgumentException("Master Key must be 16 bytes, got: "
                + masterKeyBuf.length + ", [" + masterKey + "]");
        }
        byte[] data = Buf.cat(new byte[] {(byte) newKeyVersion},
                prepareKeyPart(masterKeyBuf, keydata, 1),
                prepareKeyPart(masterKeyBuf, keydata, 2),
                prepareKeyPart(masterKeyBuf, keydata, 3));

        int p2 = 0x81; // multiple keys for keyId 1 GP 2.1.1 9.8.2.2
        APDURes res = transmit(0x80, 0xd8, currentKeyVersion, p2, data, 0);
        if (res.getSW() != 0x9000) {
            throw new SmartcardException(format("put-key currentKeyVersion: %d, newKeyVersion: %d, masterKey: %s, SW: 0x%04x",
                currentKeyVersion, newKeyVersion, masterKey, res.getSW()));
        }
        // update currentKeyVersion
        this.currentKeyVersion = newKeyVersion;
    }

    /**
     * Global Platform PUT KEY GP v2.1.1 9.8.
     * Replace key ID 1.  Uses supplied ENC, MAC and DEK keys.
     * @param currentKeyVersion current version of key
     * @param newKeyVersion new version of key
     * @param enc hex value of ENC
     * @param mac hex value of MAC
     * @param dek hex value of DEK
     * @throws SmartcardException if smartcard error
     * @throws GeneralSecurityException if crypto error
     */
    public void putKeyEncMacDek(int currentKeyVersion, int newKeyVersion, String enc, String mac, String dek)
        throws SmartcardException, GeneralSecurityException {

        log.debug("put-key currentKeyVersion: " + currentKeyVersion + ", newKeyVersion: " + newKeyVersion
                + ", ENC: " + enc + ", MAC: " + mac + ", DEK: " + dek);

        byte[] encBuf = Hex.s2b(enc);
        byte[] macBuf = Hex.s2b(mac);
        byte[] dekBuf = Hex.s2b(dek);
        if (encBuf.length != 16 || macBuf.length != 16 || dekBuf.length != 16) {
            throw new IllegalArgumentException(format(
                "ENC, MAC, and DEK keys must be 16 bytes, got: %d, %d, %d, [%s], [%s], [%s]",
                encBuf.length, macBuf.length, dekBuf.length, enc, mac, dek));
        }

        byte[] data = Buf.cat(new byte[] {(byte) newKeyVersion},
                prepareKeyPart(setOddParity(encBuf), 1),
                prepareKeyPart(setOddParity(macBuf), 2),
                prepareKeyPart(setOddParity(dekBuf), 3));

        int p2 = 0x81; // multiple keys for keyId 1 GP 2.1.1 9.8.2.2
        APDURes res = transmit(0x80, 0xd8, currentKeyVersion, p2, data, 0);
        if (res.getSW() != 0x9000) {
            throw new SmartcardException(format(
                "put-key currentKeyVersion: %d, newKeyVersion: %d, ENC: %s, MAC: %s, DEK: %s, SW: 0x%04x",
                currentKeyVersion, newKeyVersion, enc, mac, dek, res.getSW()));
        }
        // update currentKeyVersion
        this.currentKeyVersion = newKeyVersion;
    }

    /**
     * Global Platform SELECT GP v2.1.1 9.9.  Closes any existing SCP02 sessions.
     * @param aid Application ID
     * @throws SmartcardException if smartcard error
     * @throws GeneralSecurityException if crypto error
     */
    public void select(String aid) throws SmartcardException, GeneralSecurityException {
        log.debug("sending select: " + aid);
        // close SCP02
        useEncrypt = false;
        useMAC = false;
        macIV = new byte[8];

        byte[] aidbuf = Hex.s2b(aid);
        APDURes res = transmit(0x00, 0xa4, 0x04, 0x00, Hex.s2b(aid), 0);
        if (res.getSW() != 0x9000) {
            throw new SmartcardException("select " + aid + " SW: " + Integer.toHexString(res.getSW()));
        }
        currentSelected = Hex.b2s(aidbuf, 0, aidbuf.length, true); // upper case hex
    }

    /**
     * Global Platform STORE DATA GP v2.1.1 9.10.
     * @param statusType status type
     * @param stateControl state control
     * @param aid Application ID
     * @throws SmartcardException if smartcard error
     * @throws GeneralSecurityException if crypto error
     */
    public void setStatus(int statusType, int stateControl, String aid) throws SmartcardException, GeneralSecurityException {
        log.debug(format("set-status statusType: 0x%02x, stateControl: 0x%02x, aid: %s", statusType, stateControl, aid));
        APDURes res = transmit(0x80, 0xF0, statusType, stateControl, Hex.s2b(aid), null);
        if (res.getSW() != 0x9000) {
            throw new SmartcardException(format("set-status statusType: 0x%02x, stateControl: 0x%02x, aid: %s, SW: 0x%04x",
                    statusType, stateControl, aid, res.getSW()));
        }
    }

    /**
     * Global Platform STORE DATA GP v2.1.1 9.11.
     * @param p1p2 combination of p1 and p2.  E.g. 0x00cf
     * @param data hex encoded data to store
     * @throws SmartcardException if smartcard error
     * @throws GeneralSecurityException if crypto error
     */
    public void storeData(int p1p2, String data) throws SmartcardException, GeneralSecurityException {
        log.debug(format("store-data 0x%04x : %s", p1p2, data));
        APDURes res = transmit(0x80, 0xDA, p1p2 >> 8, p1p2 & 0xff, Hex.s2b(data), null);
        if (res.getSW() != 0x9000) {
            throw new SmartcardException(format("store-data 0x%04x : %s, SW: %x", p1p2, data, res.getSW()));
        }
    }

    /**
     * Wrap data with the current session DEK.
     * @param data data to wrap
     * @return data encrypted with current session DEK using DES3/ECB
     * @throws GeneralSecurityException if crypto error
     */
    public byte[] wrapData(byte[] data) throws GeneralSecurityException {
        set2TDEA(des3ecb, sessionDEK, null);
        return des3ecb.doFinal(data);
    }

    /**
     * Software crypto implementation to prepare key part for put-key using EMV diversification.
     * @param masterKey master key
     * @param keydata keydata
     * @param keyPartNum key part num
     * @return key part
     * @throws GeneralSecurityException if crypto error
     */
    private byte[] prepareKeyPart(byte[] masterKey, byte[] keydata, int keyPartNum) throws GeneralSecurityException {
        // prepare as per EMV CPS v1.1 4.1.1.6
        // KENC := DES3(KMC)[Six least significant bytes of the KEYDATA || 'F0' || '01']
        //      || DES3(KMC)[Six least significant bytes of the KEYDATA || '0' || '01']
        // KMAC => 02
        // KDEK => 03

        byte[] key = emvDiversify(masterKey, keydata, keyPartNum);
        return prepareKeyPart(key, keyPartNum);
    }

    /**
     * Software crypto implementation to prepare key part for put-key with supplied key.
     * @param key key
     * @param keyPartNum key part num
     * @return key part
     * @throws GeneralSecurityException if crypto error
     */
    private byte[] prepareKeyPart(byte[] key, int keyPartNum) throws GeneralSecurityException {
        log.debug("key: " + keyPartNum + " : " + Hex.b2s(key));
        // calculate kcv (DES3 encrypt zeros using key)
        set2TDEA(des3ecb, key, null);
        byte[] kcv = des3ecb.doFinal(new byte[8]);

        // encrypt key with current DEK
        byte[] encryptedKey = wrapData(key);

        // format for put-key GP v2.1.1 9.8.2.3.1
        // key type (0x80) || key len (0x10) || encrypted key || kcv len (0x03) || kcv

        byte[] result = new byte[22];
        result[0] = (byte) 0x80;
        result[1] = 16;
        System.arraycopy(encryptedKey, 0, result, 2, 16);
        result[18] = 3;
        System.arraycopy(kcv, 0, result, 19, 3);
        return result;
    }

    /**
     * Software crypto implementation to do EMV CPS v1.1 key diversification.
     * @param masterKey master key
     * @param keydata keydata
     * @param i i
     * @return diversified key
     * @throws GeneralSecurityException if crypto error
     */
    private byte[] emvDiversify(byte[] masterKey, byte[] keydata, int i) throws GeneralSecurityException {
        // prepare as per EMV CPS v1.1 4.1.1.6
        //    DES3(KMC)[Six least significant bytes of the KEYDATA || 'F0' || 'i']
        // || DES3(KMC)[Six least significant bytes of the KEYDATA || '0F' || 'i']

        byte[] input = new byte[16];
        System.arraycopy(keydata, keydata.length - 6, input, 0, 6);
        input[6] = (byte) 0xf0;
        input[7] = (byte) i;
        System.arraycopy(keydata, keydata.length - 6, input, 8, 6);
        input[14] = (byte) 0x0f;
        input[15] = (byte) i;

        set2TDEA(des3ecb, masterKey, null);
        return setOddParity(des3ecb.doFinal(input));
    }

    // SCP02 methods

    /**
     * Global Platform SCP02 GP v2.1.1 Appendix E.
     * Diversifies master key using keydata and EMV CPS v1.1 mechanism to produce card static ENC, MAC, DEK keys.
     * @param keyVersion key version
     * @param enc use encryption for secure channel
     * @param mac use maccing for secure channel
     * @param masterKey hex value of key
     * @param keydata key data to diversify master key using EMV CPS v1.1 to get static ENC, MAC, DEK.
     * @throws SmartcardException if card error
     * @throws GeneralSecurityException if crypto error
     */
    public void scp02(int keyVersion, boolean enc, boolean mac, String masterKey, byte[] keydata)
        throws SmartcardException, GeneralSecurityException {

        log.debug("starting SCP02.  keyVersion: " + keyVersion + ", enc: " + enc + ", mac: " + mac
                + ", masterKey: " + masterKey + ", keydata: " + keydata);

        byte[] masterKeyBuf = Hex.s2b(masterKey);
        if (masterKeyBuf.length != 16) {
            throw new IllegalArgumentException("Master Key must be 16 bytes, got: " + masterKeyBuf.length
                    + ", [" + masterKey + "]");
        }

        staticENC = emvDiversify(masterKeyBuf, keydata, 1);
        staticMAC = emvDiversify(masterKeyBuf, keydata, 2);
        staticDEK = emvDiversify(masterKeyBuf, keydata, 3);
        scp02(keyVersion, enc, mac);
    }

    /**
     * Global Platform SCP02 GP v2.1.1 Appendix E.
     * Uses provided cardStaticKeys value for ENC, MAC and DEK keys.
     * @param keyVersion key version
     * @param enc use encryption for secure channel
     * @param mac use maccing for secure channel
     * @param cardStaticKeys hex value of keys
     * @throws SmartcardException if card error
     * @throws GeneralSecurityException if crypto error
     */
    public void scp02(int keyVersion, boolean enc, boolean mac, String cardStaticKeys)
        throws SmartcardException, GeneralSecurityException {

        log.debug("starting SCP02.  keyVersion: " + keyVersion + ", enc: " + enc + ", mac: " + mac
                + ", cardStaticKeys: " + cardStaticKeys);

        byte[] masterKeyBuf = Hex.s2b(cardStaticKeys);
        if (masterKeyBuf.length != 16) {
            throw new IllegalArgumentException("Master Key must be 16 bytes, got: " + masterKeyBuf.length
                    + ", [" + cardStaticKeys + "]");
        }

        staticENC = setOddParity(masterKeyBuf);
        staticMAC = staticENC;
        staticDEK = staticENC;
        scp02(keyVersion, enc, mac);
    }

    /**
     * Global Platform SCP02 GP v2.1.1 Appendix E.
     * @param keyVersion key version
     * @param enc if true then use encryption for secure channel
     * @param mac if true then use mac for secure channel
     * @throws SmartcardException if card error
     * @throws GeneralSecurityException if crypto error
     */
    private void scp02(int keyVersion, boolean enc, boolean mac) throws SmartcardException, GeneralSecurityException {

        // initialize-update with 8 random bytes
        log.debug("sending initialize-update");
        byte[] hostChallenge = new byte[8];
        new SecureRandom().nextBytes(hostChallenge);
        APDURes res = transmit(0x80, 0x50, keyVersion, 0x00, hostChallenge, 0);
        if (res.getSW() != 0x9000) {
            throw new SmartcardException("initalize-update SW: " + Integer.toHexString(res.getSW()));
        }
        byte[] apdu = res.getBytes();
        currentKeyVersion = apdu[10] & 0xff;
        int scpVersion = apdu[11] & 0xff;
        if (scpVersion != 2) {
            log.warn("Card is not using SCP02, using version " + scpVersion + ", will continue using SCP02");
        }
        log.debug("Host Challenge      : " + Hex.b2s(hostChallenge));
        log.debug("Key div data        : " + Hex.b2s(apdu, 0, 10));
        log.debug("Current Key Version : " + currentKeyVersion);
        log.debug("SCP Version         : " + scpVersion);
        log.debug("Seq counter         : " + Hex.b2s(apdu, 12, 2));
        log.debug("Card challenge      : " + Hex.b2s(apdu, 14, 6));
        log.debug("Card cryptogram     : " + Hex.b2s(apdu, 20, 8));

        // use seq counter to create derivationData
        // see GlobalPlatform card spec 2.1.1 E.4.1
        log.debug("generating session keys");

        byte[] derivationData = new byte[16];
        System.arraycopy(apdu, 12, derivationData, 2, 2);

        // derive session MAC
        derivationData[0] = (byte) 0x01;
        derivationData[1] = (byte) 0x01;
        set2TDEA(des3cbc, staticMAC, new byte[8]);
        sessionCMAC = setOddParity(des3cbc.doFinal(derivationData));

        // derive session SENC
        derivationData[0] = (byte) 0x01;
        derivationData[1] = (byte) 0x82;
        set2TDEA(des3cbc, staticENC, new byte[8]);
        sessionSENC = setOddParity(des3cbc.doFinal(derivationData));

        // derive session DEK
        derivationData[0] = (byte) 0x01;
        derivationData[1] = (byte) 0x81;
        set2TDEA(des3cbc, staticDEK, new byte[8]);
        sessionDEK = setOddParity(des3cbc.doFinal(derivationData));

        // card cryptogram input = host challenge || seq || card challenge || 0x8000000000000000
        byte[] cardCryptogramInput = Buf.cat(hostChallenge, Buf.substring(apdu, 12, 8), new byte[8]);
        cardCryptogramInput[16] = (byte) 0x80;

        // cardCryptogram is last 8 bytes of DES-ede-cbc
        byte[] cardCryptogram;
        set2TDEA(des3cbc, sessionSENC, new byte[8]);
        cardCryptogram = des3cbc.doFinal(cardCryptogramInput);

        // compare
        if (!Hex.b2s(apdu, 20, 8).equals(Hex.b2s(cardCryptogram, 16, 8))) {
            throw new SmartcardException("cryptograms do not match:  Card sent: "
                + Hex.b2s(apdu, 20, 8) + ", expected: " + Hex.b2s(cardCryptogram, 16, 8));
        }

        // host cryptogram input = seq || card challenge || host challenge || 0x8000000000000000
        byte[] hostCryptogramInput = Buf.cat(Buf.substring(apdu, 12, 8), hostChallenge, new byte[8]);
        hostCryptogramInput[16] = (byte) 0x80;

        byte[] hostCryptogram24;
        set2TDEA(des3cbc, sessionSENC, new byte[8]);
        hostCryptogram24 = des3cbc.doFinal(hostCryptogramInput);

        // host cryptogram is last 8 bytes
        byte[] hostCryptogram = Buf.substring(hostCryptogram24, -8, 8);
        log.debug("hostCryptogram: " + Hex.b2s(hostCryptogram) + ", input: " + Hex.b2s(hostCryptogramInput));

        // set C-DECRYPTION (0x02) and C-MAC (0x01) bits GP 2.1.1 E.5.2.3
        int p1 = 0;
        if (enc) {
            p1 |= 0x02;
        }
        if (mac) {
            p1 |= 0x01;
        }

        useMAC = true; // turn mac on for external-authenticate
        log.debug("sending external-authenticate");
        res = transmit(0x80, 0x82, p1, 0x00, hostCryptogram, null);
        if (res.getSW() != 0x9000) {
            throw new SmartcardException("external-authenticate SW: " + Integer.toHexString(res.getSW()));
        }

        // set mac and enc based on input params
        useMAC = mac;
        useEncrypt = enc;
        if (useMAC && useEncrypt) {
            log.info("using secure session with encryption and maccing");
            maxDataLen = MAX_APDU_LEN_STANDARD - 16;
        } else if (useMAC) {
            log.info("using secure sessions with maccing only");
            maxDataLen = MAX_APDU_LEN_STANDARD - 8;
        } else if (useEncrypt) {
            log.info("using secure session with encryption only");
            maxDataLen = MAX_APDU_LEN_STANDARD - 8;
        } else {
            log.info("using secure session with no encryption or maccing");
            maxDataLen = MAX_APDU_LEN_STANDARD;
        }
    }

    /**
     * Smartcard Transmit with chaining and secure session if scp02 method called.
     * @param cla class
     * @param ins instruction
     * @param p1 parameter 1
     * @param p2 parameter 2
     * @param data data
     * @param le length expected
     * @return response apdu
     * @throws SmartcardException if card error
     * @throws GeneralSecurityException if crypto error
     */
    public APDURes transmit(int cla, int ins, int p1, int p2, byte[] data, Integer le)
        throws SmartcardException, GeneralSecurityException {

        if (data == null) {
            data = new byte[0];
        }
        int chainPieces = Math.max((data.length + maxDataLen - 1) / maxDataLen, 1);

        APDURes result = null;

        int offset = 0;

        // log full apdu if chaining
        if (chainPieces > 1 && log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder("gpchain > ");
            sb.append(Hex.b2s(new byte[] {(byte) cla, (byte) ins, (byte) p1, (byte) p2}));
            byte[] lebuf = new byte[0];
            if (data.length <= 255) {
                sb.append(Hex.b2s(new byte[] {(byte) data.length}));
                if (le != null) {
                    lebuf = new byte[] {le.byteValue()};
                }
            } else {
                sb.append(Hex.b2s(new byte[] {0, (byte) (data.length >> 8), (byte) data.length}));
                if (le != null) {
                    lebuf = new byte[] {(byte) (le.intValue() >> 8), le.byteValue()};
                }
            }
            sb.append(Hex.b2s(data));
            sb.append(Hex.b2s(lebuf));
            log.debug(sb.toString());
        }
        for (int i = 0; i < chainPieces; i++) {
            int lc = maxDataLen;
            cla |= 0x10; // turn on chaining

            boolean lastPiece = (i == chainPieces - 1);
            if (lastPiece) { // last piece
                lc = data.length - offset;
                cla &= 0xef; // take off chaining
            }
            byte[] piece = new byte[lc];
            System.arraycopy(data, offset, piece, 0, lc);

            result = transmitSingle(cla, ins, p1, p2, piece, lastPiece ? le : null);
            offset += maxDataLen;
        }
        return result;
    }

    /**
     * Transmit raw apdu.
     *<code>
     * case 1:  |CLA|INS|P1 |P2 |                                 len = 4
     * case 2s: |CLA|INS|P1 |P2 |LE |                             len = 5
     * case 3s: |CLA|INS|P1 |P2 |LC |...BODY...|                  len = 6..260
     * case 4s: |CLA|INS|P1 |P2 |LC |...BODY...|LE |              len = 7..261
     * case 2e: |CLA|INS|P1 |P2 |00 |LE1|LE2|                     len = 7
     * case 3e: |CLA|INS|P1 |P2 |00 |LC1|LC2|...BODY...|          len = 8..65542
     * case 4e: |CLA|INS|P1 |P2 |00 |LC1|LC2|...BODY...|LE1|LE2|  len =10..65544
     * </code>
     * @param apdu raw apdu
     * @return response apdu
     * @throws SmartcardException if card error
     * @throws GeneralSecurityException if crypto error
     */
    public APDURes transmit(byte[] apdu) throws SmartcardException, GeneralSecurityException {
        if (apdu.length < 4) {
            throw new SmartcardException("APDU must be at least 4 bytes, got apdu: " + Hex.b2s(apdu));
        }
        int cla = apdu[0];
        int ins = apdu[1];
        int p1 = apdu[2];
        int p2 = apdu[3];
        // case 1
        if (apdu.length == 4) {
            return transmit(cla, ins, p1, p2, null, null);
        // case 2s
        } else if (apdu.length == 5) {
            return transmit(cla, ins, p1, p2, null, apdu[4] & 0xff);
        }

        byte[] data = null;
        Integer le = null;
        int lc = apdu[4] & 0xff;
        if (lc > 0) {
            // case 3s
            if (apdu.length == lc + 5) {
                le = null;
            // case 4s
            } else if (apdu.length == 6 + lc) {
                le = apdu[apdu.length - 1] & 0xff;
            // error
            } else {
                throw new SmartcardException("Invalid APDU with single byte lc, lc=" + lc
                        + ", expected apdu.length of lc + (5 or 6), got " + apdu.length + ", apdu: " + Hex.b2s(apdu));
            }
            data = new byte[lc];
            System.arraycopy(apdu, 5, data, 0, data.length);
            return transmit(cla, ins, p1, p2, data, le);
        }

        // case 2e
        lc = (apdu[5] & 0xff) << 8 | (apdu[6] & 0xff);
        if (apdu.length == 7) {
            return transmit(cla, ins, p1, p2, null, lc);
        }

        // case 3e
        if (apdu.length == lc + 8) {
            le = null;
        // case 4e
        } else if (apdu.length == lc + 10) {
            le = (apdu[apdu.length - 2] & 0xff) << 8 | (apdu[apdu.length - 1] & 0xff);
        // error
        } else {
            throw new SmartcardException("Invalid APDU with double byte lc, lc=" + lc
                    + ", expected apdu.length of lc + (8 or 10), got " + apdu.length + ", apdu: " + Hex.b2s(apdu));
        }
        data = new byte[lc];
        System.arraycopy(apdu, 7, data, 0, data.length);
        return transmit(cla, ins, p1, p2, data, le);
    }

    /**
     * Transmit a single data piece (no chaining).
     * @param cla class
     * @param ins instruction
     * @param p1 parameter 1
     * @param p2 parameter 2
     * @param data data
     * @param le length expected
     * @return response apdu
     * @throws SmartcardException if card error
     * @throws GeneralSecurityException if crypto error
     */
    private APDURes transmitSingle(int cla, int ins, int p1, int p2, byte[] data, Integer le)
        throws SmartcardException, GeneralSecurityException {

        APDURes result = null;
        int apduLen = 5 + data.length;
        if (data.length == 0) { // no lc if no data
            apduLen--;
        }
        if (le != null) { // include le
            apduLen++;
        }
        byte[] apdu = new byte[apduLen];
        apdu[0] = (byte) cla;
        apdu[1] = (byte) ins;
        apdu[2] = (byte) p1;
        apdu[3] = (byte) p2;
        if (data.length > 0) {
            apdu[4] = (byte) data.length;
            System.arraycopy(data, 0, apdu, 5, data.length);
        }
        if (le != null) {
            apdu[apdu.length - 1] = le.byteValue();
        }

        long start = System.currentTimeMillis();
        log.debug("gp apdu (" + apdu.length + ") > " + Hex.b2s(apdu));
        if (useEncrypt || useMAC) {
            result = transmitSecure(cla, ins, p1, p2, data, le);
        } else {
            result = smartcard.transmit(apdu);
        }
        long timeTaken = System.currentTimeMillis() - start;
        log.debug(timeTaken + " ms gp apdu (" + result.getBytes().length + ") < " + Hex.b2s(result.getBytes()));
        return result;
    }

    /**
     * Apply encryption and mac to data (if needed).
     * @param cla class
     * @param ins instruction
     * @param p1 parameter 1
     * @param p2 parameter 2
     * @param data data
     * @param le length expected
     * @return response apdu
     * @throws SmartcardException if card error
     * @throws GeneralSecurityException if crypto error
     */
    private APDURes transmitSecure(int cla, int ins, int p1, int p2, byte[] data, Integer le)
        throws GeneralSecurityException, SmartcardException {

        cla |= 0x04;

        byte[] mac = new byte[0];
        if (useMAC) {
            // create padded apdu for input to mac
            // padding is 0x80 || 00 || 00 ...
            int padLen = 8 - ((5 + data.length) % 8);
            byte[] toBeMacced = new byte[5 + data.length + padLen];
            toBeMacced[0] = (byte) cla;
            toBeMacced[1] = (byte) ins;
            toBeMacced[2] = (byte) p1;
            toBeMacced[3] = (byte) p2;
            toBeMacced[4] = (byte) (data.length + 8);
            System.arraycopy(data, 0, toBeMacced, 5, data.length);
            toBeMacced[5 + data.length] = (byte) 0x80; // padding
            mac = mac(toBeMacced);
        }

        if (useEncrypt) {
            // padding is 0x80 || 00 || 00 ...
            byte[] pad = new byte[8 - (data.length % 8)];
            pad[0] = (byte) 0x80;
            data = Buf.cat(data, pad);
            byte[] encrypted;
            set2TDEA(des3cbc, sessionSENC, new byte[8]);
            encrypted = des3cbc.doFinal(data);

            data = encrypted;
        }

        // create apdu
        byte[] apdu = new byte[5 + data.length + mac.length + (le == null ? 0 : 1)];
        apdu[0] = (byte) cla;
        apdu[1] = (byte) ins;
        apdu[2] = (byte) p1;
        apdu[3] = (byte) p2;
        apdu[4] = (byte) (data.length + mac.length);
        System.arraycopy(data, 0, apdu, 5, data.length);
        System.arraycopy(mac, 0, apdu, 5 + data.length, mac.length);
        if (le != null) {
            apdu[apdu.length - 1] = le.byteValue();
        }
        log.debug("gp sec (" + apdu.length + ") > " + Hex.b2s(apdu));
        APDURes result = getSmartcard().transmit(apdu);
        return result;
    }

    /**
     * Calculates MAC over buf, returns mac.
     * @param buf bytes to mac
     * @return mac
     * @throws GeneralSecurityException if error doing encryptions
     */
    private byte[] mac(byte[] buf) throws GeneralSecurityException {
        int blocks = buf.length / 8;

        int offset = 0;
        for (int i = 0; i < blocks - 1; i++) {
            des1cbc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(sessionCMAC, 0, 8, "DES"), new IvParameterSpec(macIV));
            macIV = des1cbc.doFinal(buf, offset, 8);
            offset += 8;
        }

        set2TDEA(des3cbc, sessionCMAC, macIV);
        byte[] mac = des3cbc.doFinal(buf, offset, 8);

        // use the initial mac to initialise the ICV
        des1cbc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(sessionCMAC, 0, 8, "DES"), new IvParameterSpec(new byte[8]));
        macIV = des1cbc.doFinal(mac);

        return mac;
    }

    /**
     * Set odd parity on buf and return updated buf.  Buf is modified in-place.
     * @param buf buf to modify in place and return
     * @return buf that was passed in
     */
    public static byte[] setOddParity(byte[] buf) {
        for (int i = 0; i < buf.length; i++) {
            int b = buf[i] & 0xff;
            b ^= b >> 4;
            b ^= b >> 2;
            b ^= b >> 1;
            buf[i] ^= (b & 1) ^ 1;
        }
        return buf;
    }
    /**
     * Initialise a cipher for 3DES using a 2TDEA key.
     * @param cipher cipher
     * @param tdea2 16 byte 2TDEA key
     * @param iv iv ignored if null
     * @throws GeneralSecurityException if crypto error
     */
    private static void set2TDEA(Cipher cipher, byte[] tdea2, byte[] iv) throws GeneralSecurityException {
        if (tdea2.length != 16) {
            throw new InvalidKeyException("tdea2 must be 16 bytes");
        }
        byte[] key = Buf.cat(tdea2, Buf.substring(tdea2, 0, 8));
        if (iv != null) {
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DESede"), new IvParameterSpec(iv));
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DESede"));
        }
    }
}
