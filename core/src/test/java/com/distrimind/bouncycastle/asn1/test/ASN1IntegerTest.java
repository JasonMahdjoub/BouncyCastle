package com.distrimind.bouncycastle.asn1.test;

import java.math.BigInteger;

import com.distrimind.bouncycastle.asn1.ASN1Enumerated;
import com.distrimind.bouncycastle.asn1.ASN1Integer;
import com.distrimind.bouncycastle.asn1.ASN1Sequence;
import com.distrimind.bouncycastle.util.BigIntegers;
import com.distrimind.bouncycastle.util.Properties;
import com.distrimind.bouncycastle.util.encoders.Base64;
import com.distrimind.bouncycastle.util.encoders.Hex;
import com.distrimind.bouncycastle.util.test.SimpleTest;

public class ASN1IntegerTest
    extends SimpleTest
{
    private static final byte[] suspectKey = Base64.decode(
        "MIGJAoGBAHNc+iExm94LUrJdPSJ4QJ9tDRuvaNmGVHpJ4X7a5zKI02v+2E7RotuiR2MHDJfVJkb9LUs2kb3XBlyENhtMLsbeH+3Muy3" +
            "hGDlh/mLJSh1s4c5jDKBRYOHom7Uc8wP0P2+zBCA+OEdikNDFBaP5PbR2Xq9okG2kPh35M2quAiMTAgMBAAE=");

    public String getName()
    {
        return "ASN1Integer";
    }

    public void performTest()
        throws Exception
    {
        System.setProperty("com.distrimind.bouncycastle.asn1.allow_unsafe_integer", "true");

        ASN1Sequence.getInstance(suspectKey);

        testValidEncodingSingleByte();
        testValidEncodingMultiByte();
        testInvalidEncoding_00();
        testInvalidEncoding_ff();
        testInvalidEncoding_00_32bits();
        testInvalidEncoding_ff_32bits();
        //testLooseInvalidValidEncoding_FF_32B();
        //testLooseInvalidValidEncoding_zero_32B();
        testLooseValidEncoding_zero_32BAligned();
        testLooseValidEncoding_FF_32BAligned();
        testLooseValidEncoding_FF_32BAligned_1not0();
        testLooseValidEncoding_FF_32BAligned_2not0();
        testOversizedEncoding();
        
        System.setProperty("com.distrimind.bouncycastle.asn1.allow_unsafe_integer", "true");

        new ASN1Integer(Hex.decode("ffda47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b0e"));

        new ASN1Enumerated(Hex.decode("005a47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b0e"));

        System.setProperty("com.distrimind.bouncycastle.asn1.allow_unsafe_integer", "false");
        
        try
        {
            new ASN1Integer(Hex.decode("ffda47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b"));

            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("malformed integer", e.getMessage());
        }

        isTrue(!Properties.setThreadOverride("com.distrimind.bouncycastle.asn1.allow_unsafe_integer", true));
        
        new ASN1Integer(Hex.decode("ffda47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b"));

        isTrue(Properties.removeThreadOverride("com.distrimind.bouncycastle.asn1.allow_unsafe_integer"));

        try
        {
            ASN1Sequence.getInstance(suspectKey);

            fail("no exception");
        }
        catch (IllegalArgumentException e)
        { 
            isEquals("test 1: " + e.getMessage(), "failed to construct sequence from byte[]: malformed integer", e.getMessage());
        }

        try
        {
            new ASN1Integer(Hex.decode("ffda47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b0e"));

            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("malformed integer", e.getMessage());
        }

        try
        {
            new ASN1Enumerated(Hex.decode("ffda47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b0e"));

            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("malformed enumerated", e.getMessage());
        }

        try
        {
            new ASN1Enumerated(Hex.decode("005a47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b0e"));

            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("malformed enumerated", e.getMessage());
        }
    }

    /**
     * Ensure existing single byte behavior.
     */
    public void testValidEncodingSingleByte()
        throws Exception
    {
        System.setProperty("com.distrimind.bouncycastle.asn1.allow_unsafe_integer", "false");
        //
        // Without property, single byte.
        //
        byte[] rawInt = Hex.decode("10");
        ASN1Integer i = new ASN1Integer(rawInt);
        checkIntValue(i, 16);

        //
        // With property set.
        //
        System.setProperty("com.distrimind.bouncycastle.asn1.allow_unsafe_integer", "true");

        rawInt = Hex.decode("10");
        i = new ASN1Integer(rawInt);
        checkIntValue(i, 16);
    }

    public void testValidEncodingMultiByte()
        throws Exception
    {
        System.setProperty("com.distrimind.bouncycastle.asn1.allow_unsafe_integer", "false");
        //
        // Without property, single byte.
        //
        byte[] rawInt = Hex.decode("10FF");
        ASN1Integer i = new ASN1Integer(rawInt);
        checkIntValue(i, 4351);

        //
        // With property set.
        //
        System.setProperty("com.distrimind.bouncycastle.asn1.allow_unsafe_integer", "true");

        rawInt = Hex.decode("10FF");
        i = new ASN1Integer(rawInt);
        checkIntValue(i, 4351);
    }

    public void testInvalidEncoding_00()
        throws Exception
    {
        System.setProperty("com.distrimind.bouncycastle.asn1.allow_unsafe_integer", "false");
        try
        {
            byte[] rawInt = Hex.decode("0010FF");
            new ASN1Integer(rawInt);
            fail("Expecting illegal argument exception.");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("malformed integer", e.getMessage());
        }
    }

    public void testInvalidEncoding_ff()
        throws Exception
    {
        System.setProperty("com.distrimind.bouncycastle.asn1.allow_unsafe_integer", "false");
        try
        {
            byte[] rawInt = Hex.decode("FF81FF");
            new ASN1Integer(rawInt);
            fail("Expecting illegal argument exception.");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("malformed integer", e.getMessage());
        }
    }

    public void testInvalidEncoding_00_32bits()
        throws Exception
    {
        System.setProperty("com.distrimind.bouncycastle.asn1.allow_unsafe_integer", "false");
        //
        // Check what would pass loose validation fails outside of loose validation.
        //
        try
        {
            byte[] rawInt = Hex.decode("0000000010FF");
            new ASN1Integer(rawInt);
            fail("Expecting illegal argument exception.");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("malformed integer", e.getMessage());
        }
    }

    public void testInvalidEncoding_ff_32bits()
        throws Exception
    {
        System.setProperty("com.distrimind.bouncycastle.asn1.allow_unsafe_integer", "false");
        //
        // Check what would pass loose validation fails outside of loose validation.
        //
        try
        {
            byte[] rawInt = Hex.decode("FFFFFFFF01FF");
            new ASN1Integer(rawInt);
            fail("Expecting illegal argument exception.");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("malformed integer", e.getMessage());
        }
    }

    /*
     Unfortunately it turns out that integers stored without sign bits that are assumed to be
     unsigned.. this means a string of FF may occur and then the user will call getPositiveValue().
     Sigh..
    public void testLooseInvalidValidEncoding_zero_32B()
        throws Exception
    {
        System.setProperty("com.distrimind.bouncycastle.asn1.allow_unsafe_integer", "false");
        //
        // Should still fail as loose validation only permits 3 leading 0x00 bytes.
        //
        try
        {
            System.getProperties().put("com.distrimind.bouncycastle.asn1.allow_unsafe_integer", "true");
            byte[] rawInt = Hex.decode("0000000010FF");
            ASN1Integer i = new ASN1Integer(rawInt);
            fail("Expecting illegal argument exception.");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("malformed integer", e.getMessage());
        }
    }

    public void testLooseInvalidValidEncoding_FF_32B()
        throws Exception
    {
        System.setProperty("com.distrimind.bouncycastle.asn1.allow_unsafe_integer", "false");
        //
        // Should still fail as loose validation only permits 3 leading 0xFF bytes.
        //
        try
        {
            System.getProperties().put("com.distrimind.bouncycastle.asn1.allow_unsafe_integer", "true");
            byte[] rawInt = Hex.decode("FFFFFFFF10FF");
            ASN1Integer i = new ASN1Integer(rawInt);
            fail("Expecting illegal argument exception.");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("malformed integer", e.getMessage());
        }
    }
    */

    public void testLooseValidEncoding_zero_32BAligned()
        throws Exception
    {
        System.setProperty("com.distrimind.bouncycastle.asn1.allow_unsafe_integer", "false");
        //
        // Should pass as loose validation permits 3 leading 0x00 bytes.
        //

        System.getProperties().put("com.distrimind.bouncycastle.asn1.allow_unsafe_integer", "true");
        byte[] rawInt = Hex.decode("00000010FF000000");
        ASN1Integer i = new ASN1Integer(rawInt);
        checkLongValue(i, 72997666816L);
    }

    public void testLooseValidEncoding_FF_32BAligned()
        throws Exception
    {
        System.setProperty("com.distrimind.bouncycastle.asn1.allow_unsafe_integer", "false");
        //
        // Should pass as loose validation permits 3

        System.getProperties().put("com.distrimind.bouncycastle.asn1.allow_unsafe_integer", "true");
        byte[] rawInt = Hex.decode("FFFFFF10FF000000");
        ASN1Integer i = new ASN1Integer(rawInt);
        checkLongValue(i, -1026513960960L);
    }

    public void testLooseValidEncoding_FF_32BAligned_1not0()
        throws Exception
    {
        System.setProperty("com.distrimind.bouncycastle.asn1.allow_unsafe_integer", "false");
        //
        // Should pass as loose validation permits 3 leading 0xFF bytes.
        //

        System.getProperties().put("com.distrimind.bouncycastle.asn1.allow_unsafe_integer", "true");
        byte[] rawInt = Hex.decode("FFFEFF10FF000000");
        ASN1Integer i = new ASN1Integer(rawInt);
        checkLongValue(i, -282501490671616L);
    }

    public void testLooseValidEncoding_FF_32BAligned_2not0()
        throws Exception
    {
        System.setProperty("com.distrimind.bouncycastle.asn1.allow_unsafe_integer", "false");
        //
        // Should pass as loose validation permits 3 leading 0xFF bytes.
        //

        System.getProperties().put("com.distrimind.bouncycastle.asn1.allow_unsafe_integer", "true");
        byte[] rawInt = Hex.decode("FFFFFE10FF000000");
        ASN1Integer i = new ASN1Integer(rawInt);
        checkLongValue(i, -2126025588736L);
    }

    public void testOversizedEncoding()
        throws Exception
    {
        System.setProperty("com.distrimind.bouncycastle.asn1.allow_unsafe_integer", "false");
        //
        // Should pass as loose validation permits 3 leading 0xFF bytes.
        //

        System.getProperties().put("com.distrimind.bouncycastle.asn1.allow_unsafe_integer", "true");
        byte[] rawInt = Hex.decode("FFFFFFFE10FF000000000000");
        ASN1Integer i = new ASN1Integer(rawInt);
        isEquals(new BigInteger(Hex.decode("FFFFFFFE10FF000000000000")), i.getValue());

        rawInt = Hex.decode("FFFFFFFFFE10FF000000000000");
        try
        {
            new ASN1Integer(rawInt);
        }
        catch (IllegalArgumentException e)
        {
            isEquals("malformed integer", e.getMessage());
        }
    }

    private void checkIntValue(ASN1Integer i, int n)
    {
        BigInteger val = i.getValue();
        isEquals(val.intValue(), n);
        isEquals(BigIntegers.intValueExact(val), n);
        isEquals(i.intValueExact(), n);
        isTrue(i.hasValue(n));
    }

    private void checkLongValue(ASN1Integer i, long n)
    {
        BigInteger val = i.getValue();
        isEquals(val.longValue(), n);
        isEquals(BigIntegers.longValueExact(val), n);
        isEquals(i.longValueExact(), n);
        isTrue(i.hasValue(n));
    }

    public static void main(
        String[] args)
    {
        runTest(new ASN1IntegerTest());
    }
}
