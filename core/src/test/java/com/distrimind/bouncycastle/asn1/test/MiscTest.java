package com.distrimind.bouncycastle.asn1.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import com.distrimind.bouncycastle.asn1.ASN1Encodable;
import com.distrimind.bouncycastle.asn1.ASN1Enumerated;
import com.distrimind.bouncycastle.asn1.ASN1InputStream;
import com.distrimind.bouncycastle.asn1.ASN1Integer;
import com.distrimind.bouncycastle.asn1.ASN1OutputStream;
import com.distrimind.bouncycastle.asn1.ASN1Primitive;
import com.distrimind.bouncycastle.asn1.BERSequence;
import com.distrimind.bouncycastle.asn1.DERBitString;
import com.distrimind.bouncycastle.asn1.DERIA5String;
import com.distrimind.bouncycastle.internal.asn1.misc.CAST5CBCParameters;
import com.distrimind.bouncycastle.internal.asn1.misc.IDEACBCPar;
import com.distrimind.bouncycastle.internal.asn1.misc.NetscapeCertType;
import com.distrimind.bouncycastle.internal.asn1.misc.NetscapeRevocationURL;
import com.distrimind.bouncycastle.internal.asn1.misc.VerisignCzagExtension;
import com.distrimind.bouncycastle.util.Arrays;
import com.distrimind.bouncycastle.util.encoders.Base64;
import com.distrimind.bouncycastle.util.test.SimpleTest;

public class MiscTest
    extends SimpleTest
{
    public void shouldFailOnExtraData()
        throws Exception
    {
        // basic construction
        DERBitString s1 = new DERBitString(new byte[0], 0);

        ASN1Primitive.fromByteArray(s1.getEncoded());

        ASN1Primitive.fromByteArray(new BERSequence(s1).getEncoded());

        try
        {
            ASN1Primitive obj = ASN1Primitive.fromByteArray(Arrays.concatenate(s1.getEncoded(), new byte[1]));
            fail("no exception");
        }
        catch (IOException e)
        {
            if (!"Extra data detected in stream".equals(e.getMessage()))
            {
                fail("wrong exception");
            }
        }
    }

    public void asn1IntegerTest()
        throws Exception
    {
        System.setProperty("com.distrimind.bouncycastle.asn1.allow_unsafe_integer", "false");

        try
        {
            new ASN1Integer(new byte[] { 0, 0, 0, 1});
            fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("wrong exc 1: " + e.getMessage(), "malformed integer".equals(e.getMessage()));
        }

        try
        {
            new ASN1Integer(new byte[] {(byte)0xff, (byte)0x80, 0, 1});
            fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("wrong exc 2: " + e.getMessage(), "malformed integer".equals(e.getMessage()));
        }

        try
        {
            new ASN1Enumerated(new byte[] { 0, 0, 0, 1});
            fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("wrong exc 3: " + e.getMessage(), "malformed enumerated".equals(e.getMessage()));
        }

        try
        {
            new ASN1Enumerated(new byte[] {(byte)0xff, (byte)0x80, 0, 1});
            fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("wrong exc 4: " + e.getMessage(), "malformed enumerated".equals(e.getMessage()));
        }
    }

    public void performTest()
        throws Exception
    {
        byte[]  testIv = { 1, 2, 3, 4, 5, 6, 7, 8 };
        
        ASN1Encodable[]     values = {
            new CAST5CBCParameters(testIv, 128), 
            new NetscapeCertType(NetscapeCertType.smime),    
            new VerisignCzagExtension(new DERIA5String("hello")),
            new IDEACBCPar(testIv),        
            new NetscapeRevocationURL(new DERIA5String("http://test"))
        };
        
        byte[] data = Base64.decode("MA4ECAECAwQFBgcIAgIAgAMCBSAWBWhlbGxvMAoECAECAwQFBgcIFgtodHRwOi8vdGVzdA==");

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ASN1OutputStream aOut = ASN1OutputStream.create(bOut);

        for (int i = 0; i != values.length; i++)
        {
            aOut.writeObject(values[i]);
        }

        if (!areEqual(bOut.toByteArray(), data))
        {
            fail("Failed data check");
        }

        ASN1InputStream aIn = new ASN1InputStream(data);

        for (int i = 0; i != values.length; i++)
        {
            ASN1Primitive o = aIn.readObject();
            if (!values[i].equals(o))
            {
                fail("Failed equality test for " + o);
            }

            if (o.hashCode() != values[i].hashCode())
            {
                fail("Failed hashCode test for " + o);
            }
        }

        shouldFailOnExtraData();
        asn1IntegerTest();
    }

    public String getName()
    {
        return "Misc";
    }

    public static void main(
        String[] args)
    {
        runTest(new MiscTest());
    }
}
