package com.distrimind.bouncycastle.asn1.cmc.test;

import java.util.Date;

import com.distrimind.bouncycastle.asn1.ASN1Enumerated;
import com.distrimind.bouncycastle.asn1.ASN1GeneralizedTime;
import com.distrimind.bouncycastle.asn1.ASN1Integer;
import com.distrimind.bouncycastle.asn1.ASN1OctetString;
import com.distrimind.bouncycastle.asn1.ASN1UTF8String;
import com.distrimind.bouncycastle.asn1.DEROctetString;
import com.distrimind.bouncycastle.asn1.DERSequence;
import com.distrimind.bouncycastle.asn1.DERUTF8String;
import com.distrimind.bouncycastle.asn1.cmc.RevokeRequest;
import com.distrimind.bouncycastle.asn1.x500.X500Name;
import com.distrimind.bouncycastle.asn1.x500.X500NameBuilder;
import com.distrimind.bouncycastle.asn1.x500.style.BCStyle;
import com.distrimind.bouncycastle.asn1.x509.CRLReason;
import com.distrimind.bouncycastle.util.Pack;
import com.distrimind.bouncycastle.util.test.SimpleTest;


public class RevokeRequestTest
    extends SimpleTest
{
    public static void main(String[] args)
    {
        runTest(new RevokeRequestTest());
    }

    public String getName()
    {
        return "RevokeRequestTest";
    }

    public void performTest()
        throws Exception
    {


        X500NameBuilder builder = new X500NameBuilder();
        builder.addRDN(BCStyle.OU, "Bouncycastle");

        X500Name name = builder.build();

        for (int t = 0; t < 8; t++)
        {
            ASN1GeneralizedTime invalidityDate = null;
            ASN1OctetString passphrase = null;
            ASN1UTF8String comment = null;

            if ((t & 1) == 1)
            {
                invalidityDate = new ASN1GeneralizedTime(new Date());
            }
            if ((t & 2) == 2)
            {
                passphrase = new DEROctetString(Pack.longToBigEndian(System.currentTimeMillis()));
            }
            if ((t & 4) == 4)
            {
                comment = new DERUTF8String("T" + Long.toOctalString(System.currentTimeMillis()));
            }

            RevokeRequest rr = new RevokeRequest(
                name,
                new ASN1Integer(12L),
                CRLReason.getInstance(new ASN1Enumerated(CRLReason.certificateHold)),
                invalidityDate,
                passphrase,
                comment);
            byte[] b = rr.getEncoded();
            RevokeRequest rrResp = RevokeRequest.getInstance(b);

            isEquals("issuerName", rr.getName(), rrResp.getName());
            isEquals("serialNumber", rr.getSerialNumber(), rrResp.getSerialNumber());
            isEquals("reason", rr.getReason(), rrResp.getReason());
            isEquals("invalidityDate", rr.getInvalidityDate(), rrResp.getInvalidityDate());
            isTrue("passphrase", areEqual(rr.getPassPhrase(), rrResp.getPassPhrase()));
            isEquals("comment", rr.getCommentUTF8(), rrResp.getCommentUTF8());
        }

        try
        {
            RevokeRequest.getInstance(new DERSequence());
            fail("Sequence is less that 3");
        }
        catch (Throwable t)
        {
            isEquals("Exception type", t.getClass(), IllegalArgumentException.class);
        }

    }
}
