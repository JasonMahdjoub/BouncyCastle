package com.distrimind.bouncycastle.asn1.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import com.distrimind.bouncycastle.asn1.ASN1Encoding;
import com.distrimind.bouncycastle.asn1.ASN1InputStream;
import com.distrimind.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.distrimind.bouncycastle.asn1.ASN1Primitive;
import com.distrimind.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import com.distrimind.bouncycastle.util.encoders.Hex;
import com.distrimind.bouncycastle.util.test.SimpleTest;


/**
 * X.690 test example
 */
public class OIDTest
    extends SimpleTest
{
    byte[]    req1 = Hex.decode("0603813403");
    byte[]    req2 = Hex.decode("06082A36FFFFFFDD6311");

    public String getName()
    {
        return "OID";
    }
    
    private void recodeCheck(
        String oid, 
        byte[] enc) 
        throws IOException
    {
        ByteArrayInputStream     bIn = new ByteArrayInputStream(enc);
        ASN1InputStream          aIn = new ASN1InputStream(bIn);

        ASN1ObjectIdentifier      o = new ASN1ObjectIdentifier(oid);
        ASN1ObjectIdentifier      encO = (ASN1ObjectIdentifier)aIn.readObject();
        
        if (!o.equals(encO))
        {
            fail("oid ID didn't match", o, encO);
        }

        byte[] bytes = o.getEncoded(ASN1Encoding.DER);

        if (bytes.length != enc.length)
        {
            fail("failed length test");
        }

        for (int i = 0; i != enc.length; i++)
        {
            if (bytes[i] != enc[i])
            {
                fail("failed comparison test", new String(Hex.encode(enc)), new String(Hex.encode(bytes)));
            }
        }
    }
    
    private void validOidCheck(
        String  oid)
        throws IOException
    {
        isTrue(ASN1ObjectIdentifier.tryFromID(oid) != null);

        ASN1ObjectIdentifier o = new ASN1ObjectIdentifier(oid);
        o = (ASN1ObjectIdentifier)ASN1Primitive.fromByteArray(o.getEncoded());
        if (!o.getId().equals(oid))
        {
            fail("failed oid check for " + oid);
        }
    }

    private void invalidOidCheck(
        String oid)
    {
        isTrue(ASN1ObjectIdentifier.tryFromID(oid) == null);

        try
        {
            new ASN1ObjectIdentifier(oid);
            fail("failed to catch bad oid: " + oid);
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void branchCheck(String stem, String branch)
    {
        String expected = stem + "." + branch;
        String actual = new ASN1ObjectIdentifier(stem).branch(branch).getId();

        if (!expected.equals(actual))
        {
            fail("failed 'branch' check for " + stem + "/" + branch);
        }
    }

    private void onCheck(String stem, String test, boolean expected)
    {
        if (expected != new ASN1ObjectIdentifier(test).on(new ASN1ObjectIdentifier(stem)))
        {
            fail("failed 'on' check for " + stem + "/" + test);
        }
    }

    private void testIntern()
    {
        ASN1ObjectIdentifier oid1 = new ASN1ObjectIdentifier("2.2.100").intern();
        ASN1ObjectIdentifier oid2 = new ASN1ObjectIdentifier("2.2.100").intern();

        isTrue(oid2 != null);
        isEquals(oid1, oid2);
    }

    public void performTest()
        throws IOException
    {
        recodeCheck("2.100.3", req1);
        recodeCheck("1.2.54.34359733987.17", req2);
        
        validOidCheck(PKCSObjectIdentifiers.pkcs_9_at_contentType.getId());
        validOidCheck("0.1");
        validOidCheck("1.0");
        validOidCheck("1.0.2");
        validOidCheck("1.0.20");
        validOidCheck("1.0.200");
        validOidCheck("1.1.127.32512.8323072.2130706432.545460846592.139637976727552.35747322042253312.9151314442816847872");
        validOidCheck("1.2.123.12345678901.1.1.1");
        validOidCheck("2.25.196556539987194312349856245628873852187.1");
        validOidCheck("0.0");
        validOidCheck("0.0.1");
        validOidCheck("0.39");
        validOidCheck("0.39.1");
        validOidCheck("1.0");
        validOidCheck("1.0.1");
        validOidCheck("1.39");
        validOidCheck("1.39.1");
        validOidCheck("2.0");
        validOidCheck("2.0.1");
        validOidCheck("2.40");
        validOidCheck("2.40.1");

        invalidOidCheck("0");
        invalidOidCheck("1");
        invalidOidCheck("2");
        invalidOidCheck("3.1");
        invalidOidCheck("0.01");
        invalidOidCheck("00.1");
        invalidOidCheck("1.00.2");
        invalidOidCheck("1.0.02");
        invalidOidCheck("1.2.00");
        invalidOidCheck("..1");
        invalidOidCheck("192.168.1.1");
        invalidOidCheck(".123452");
        invalidOidCheck("1.");
        invalidOidCheck("1.345.23.34..234");
        invalidOidCheck("1.345.23.34.234.");
        invalidOidCheck(".12.345.77.234");
        invalidOidCheck(".12.345.77.234.");
        invalidOidCheck("1.2.3.4.A.5");
        invalidOidCheck("1,2");
        invalidOidCheck("0.40");
        invalidOidCheck("0.40.1");
        invalidOidCheck("0.100");
        invalidOidCheck("0.100.1");
        invalidOidCheck("1.40");
        invalidOidCheck("1.40.1");
        invalidOidCheck("1.100");
        invalidOidCheck("1.100.1");

        branchCheck("1.1", "2.2");

        onCheck("1.1", "1.1", false);
        onCheck("1.1", "1.2", false);
        onCheck("1.1", "1.2.1", false);
        onCheck("1.1", "2.1", false);
        onCheck("1.1", "1.11", false);
        onCheck("1.12", "1.1.2", false);
        onCheck("1.1", "1.1.1", true);
        onCheck("1.1", "1.1.2", true);
        onCheck("1.2.3.4.5.6", "1.2.3.4.5.6", false);
        onCheck("1.2.3.4.5.6", "1.2.3.4.5.6.7", true);
        onCheck("1.2.3.4.5.6", "1.2.3.4.5.6.7.8", true);

        testIntern();
    }

    public static void main(
        String[]    args)
    {
        runTest(new OIDTest());
    }
}
