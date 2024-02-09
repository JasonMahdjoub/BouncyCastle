package com.distrimind.bouncycastle.asn1.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Date;

import com.distrimind.bouncycastle.asn1.ASN1Boolean;
import com.distrimind.bouncycastle.asn1.ASN1Enumerated;
import com.distrimind.bouncycastle.asn1.ASN1InputStream;
import com.distrimind.bouncycastle.asn1.ASN1Integer;
import com.distrimind.bouncycastle.asn1.ASN1ObjectDescriptor;
import com.distrimind.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.distrimind.bouncycastle.asn1.ASN1OutputStream;
import com.distrimind.bouncycastle.asn1.ASN1Primitive;
import com.distrimind.bouncycastle.asn1.ASN1RelativeOID;
import com.distrimind.bouncycastle.asn1.BEROctetString;
import com.distrimind.bouncycastle.asn1.BERSequence;
import com.distrimind.bouncycastle.asn1.BERSet;
import com.distrimind.bouncycastle.asn1.BERTaggedObject;
import com.distrimind.bouncycastle.asn1.DERBMPString;
import com.distrimind.bouncycastle.asn1.DERBitString;
import com.distrimind.bouncycastle.asn1.DERGeneralString;
import com.distrimind.bouncycastle.asn1.DERGeneralizedTime;
import com.distrimind.bouncycastle.asn1.DERGraphicString;
import com.distrimind.bouncycastle.asn1.DERIA5String;
import com.distrimind.bouncycastle.asn1.DERNull;
import com.distrimind.bouncycastle.asn1.DERNumericString;
import com.distrimind.bouncycastle.asn1.DEROctetString;
import com.distrimind.bouncycastle.asn1.DERPrintableString;
import com.distrimind.bouncycastle.asn1.DERSequence;
import com.distrimind.bouncycastle.asn1.DERSet;
import com.distrimind.bouncycastle.asn1.DERT61String;
import com.distrimind.bouncycastle.asn1.DERTaggedObject;
import com.distrimind.bouncycastle.asn1.DERUTCTime;
import com.distrimind.bouncycastle.asn1.DERUTF8String;
import com.distrimind.bouncycastle.asn1.DERUniversalString;
import com.distrimind.bouncycastle.asn1.DERVideotexString;
import com.distrimind.bouncycastle.asn1.DERVisibleString;
import com.distrimind.bouncycastle.util.Strings;
import com.distrimind.bouncycastle.util.encoders.Hex;
import com.distrimind.bouncycastle.util.test.SimpleTestResult;
import com.distrimind.bouncycastle.util.test.Test;
import com.distrimind.bouncycastle.util.test.TestResult;

public class EqualsAndHashCodeTest
    implements Test
{
    public TestResult perform()
    {
        byte[]    data = { 0, 1, 0, 1, 0, 0, 1 };
        
        ASN1Primitive    values[] = {
                new BEROctetString(data),
                new BERSequence(new DERPrintableString("hello world")),
                new BERSet(new DERPrintableString("hello world")),
                new BERTaggedObject(0, new DERPrintableString("hello world")),
                new DERBitString(data),
                new DERBMPString("hello world"),
                ASN1Boolean.getInstance(true),
                ASN1Boolean.getInstance(false),
                new ASN1Enumerated(100),
                new DERGeneralizedTime("20070315173729Z"),
                new DERGeneralString("hello world"),
                new DERIA5String("hello"),
                new ASN1Integer(1000),
                DERNull.INSTANCE,
                new DERNumericString("123456"),
                new ASN1ObjectIdentifier("1.1.1.10000.1"),
                new ASN1RelativeOID("3.2.0.123456"),
                new ASN1ObjectDescriptor(new DERGraphicString(Hex.decode("feedface"))),
                new DEROctetString(data),
                new DERPrintableString("hello world"),
                new DERSequence(new DERPrintableString("hello world")),
                new DERSet(new DERPrintableString("hello world")),
                new DERT61String("hello world"),
                new DERTaggedObject(0, new DERPrintableString("hello world")),
                new DERUniversalString(data),
                new DERUTCTime(new Date()),
                new DERUTF8String("hello world"),
                new DERVisibleString("hello world") ,
                new DERGraphicString(Hex.decode("deadbeef")),
                new DERVideotexString(Strings.toByteArray("Hello World"))
            };
        
        try
        {
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            ASN1OutputStream aOut = ASN1OutputStream.create(bOut);

            for (int i = 0; i != values.length; i++)
            {
                aOut.writeObject(values[i]);
            }

            ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
            ASN1InputStream aIn = new ASN1InputStream(bIn);

            for (int i = 0; i != values.length; i++)
            {
                ASN1Primitive o = aIn.readObject();
                if (!o.equals(values[i]))
                {
                    return new SimpleTestResult(false, getName() + ": Failed equality test for " + o.getClass());
                }
                
                if (o.hashCode() != values[i].hashCode())
                {
                    return new SimpleTestResult(false, getName() + ": Failed hashCode test for " + o.getClass());
                }
            }
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": Failed - exception " + e.toString(), e);
        }
        
        return new SimpleTestResult(true, getName() + ": Okay");
    }

    public String getName()
    {
        return "EqualsAndHashCode";
    }

    public static void main(
        String[] args)
    {
        EqualsAndHashCodeTest    test = new EqualsAndHashCodeTest();
        TestResult      result = test.perform();

        System.out.println(result);
    }
}
