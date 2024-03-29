package com.distrimind.bouncycastle.asn1.test;

import java.io.IOException;

import com.distrimind.bouncycastle.asn1.ASN1BitString;
import com.distrimind.bouncycastle.asn1.ASN1Encoding;
import com.distrimind.bouncycastle.asn1.ASN1Primitive;
import com.distrimind.bouncycastle.asn1.BERBitString;
import com.distrimind.bouncycastle.asn1.DERBitString;
import com.distrimind.bouncycastle.asn1.DLBitString;
import com.distrimind.bouncycastle.asn1.x509.KeyUsage;
import com.distrimind.bouncycastle.util.Arrays;
import com.distrimind.bouncycastle.util.encoders.Hex;
import com.distrimind.bouncycastle.util.test.SimpleTest;
import com.distrimind.bouncycastle.util.test.TestResult;

public class BitStringTest
    extends SimpleTest
{
    private void testConstructed()
        throws Exception
    {
        ASN1BitString s1 = new BERBitString(new byte[1500], 1);
        ASN1BitString s2 = ASN1BitString.getInstance(s1.getEncoded());
    }

    private void testZeroLengthStrings()
        throws Exception
    {
        // basic construction
        DERBitString s1 = new DERBitString(new byte[0], 0);

        // check getBytes()
        s1.getBytes();

        // check encoding/decoding
        DERBitString derBit = (DERBitString)ASN1Primitive.fromByteArray(s1.getEncoded());

        if (!Arrays.areEqual(s1.getEncoded(), Hex.decode("030100")))
        {
            fail("zero encoding wrong");
        }

        try
        {
            new DERBitString(null, 1);
            fail("exception not thrown");
        }
        catch (NullPointerException e)
        {
            if (!"'data' cannot be null".equals(e.getMessage()))
            {
                fail("Unexpected exception: " + e.getMessage());
            }
        }

        try
        {
            new DERBitString(new byte[0], 1);
            fail("exception not thrown");
        }
        catch (IllegalArgumentException e)
        {
            if (!"zero length data with non-zero pad bits".equals(e.getMessage()))
            {
                fail("Unexpected exception");
            }
        }

        try
        {
            new DERBitString(new byte[1], 8);
            fail("exception not thrown");
        }
        catch (IllegalArgumentException e)
        {
            if (!"pad bits cannot be greater than 7 or less than 0".equals(e.getMessage()))
            {
                fail("Unexpected exception");
            }
        }

        DERBitString s2 = new DERBitString(0);
        if (!Arrays.areEqual(s1.getEncoded(), s2.getEncoded()))
        {
            fail("zero encoding wrong");
        }
    }

    private void testRandomPadBits()
        throws Exception
    {
        byte[] test = Hex.decode("030206c0");

        byte[] test1 = Hex.decode("030206f0");
        byte[] test2 = Hex.decode("030206c1");
        byte[] test3 = Hex.decode("030206c7");
        byte[] test4 = Hex.decode("030206d1");

        encodingCheck(test, test1);
        encodingCheck(test, test2);
        encodingCheck(test, test3);
        encodingCheck(test, test4);
    }

    private void encodingCheck(byte[] derData, byte[] dlData)
        throws IOException
    {
        if (Arrays.areEqual(derData, ASN1Primitive.fromByteArray(dlData).getEncoded()))
        {
            fail("failed DL check");
        }
        ASN1BitString dl = ASN1BitString.getInstance(dlData);

        isTrue("DL test failed", dl instanceof DLBitString);
        if (!Arrays.areEqual(derData, ASN1Primitive.fromByteArray(dlData).getEncoded(ASN1Encoding.DER)))
        {
            fail("failed DER check");
        }
        try
        {
            /*
             * Allow this since getInstance should work for
             * "an object that can be converted into [an ASN1BitString]".
             */
            ASN1BitString.getInstance(dlData);
        }
        catch (IllegalArgumentException e)
        {
            fail("failed DL encoding conversion");
        }
        ASN1BitString der = ASN1BitString.getInstance(derData);
        isTrue("DER test failed", der instanceof DERBitString);
    }

    public void performTest()
        throws Exception
    {
        KeyUsage k = new KeyUsage(KeyUsage.digitalSignature);
        if ((k.getBytes()[0] != (byte)KeyUsage.digitalSignature) || (k.getPadBits() != 7))
        {
            fail("failed digitalSignature");
        }

        k = new KeyUsage(KeyUsage.nonRepudiation);
        if ((k.getBytes()[0] != (byte)KeyUsage.nonRepudiation) || (k.getPadBits() != 6))
        {
            fail("failed nonRepudiation");
        }

        k = new KeyUsage(KeyUsage.keyEncipherment);
        if ((k.getBytes()[0] != (byte)KeyUsage.keyEncipherment) || (k.getPadBits() != 5))
        {
            fail("failed keyEncipherment");
        }

        k = new KeyUsage(KeyUsage.cRLSign);
        if ((k.getBytes()[0] != (byte)KeyUsage.cRLSign) || (k.getPadBits() != 1))
        {
            fail("failed cRLSign");
        }

        k = new KeyUsage(KeyUsage.decipherOnly);
        if ((k.getBytes()[1] != (byte)(KeyUsage.decipherOnly >> 8)) || (k.getPadBits() != 7))
        {
            fail("failed decipherOnly");
        }

        // test for zero length bit string
        try
        {
            ASN1Primitive.fromByteArray(new DERBitString(new byte[0], 0).getEncoded());
        }
        catch (IOException e)
        {
            fail(e.toString());
        }

        testConstructed();
        testRandomPadBits();
        testZeroLengthStrings();
    }

    public String getName()
    {
        return "BitString";
    }

    public static void main(
        String[] args)
    {
        BitStringTest test = new BitStringTest();
        TestResult result = test.perform();

        System.out.println(result);
    }
}
