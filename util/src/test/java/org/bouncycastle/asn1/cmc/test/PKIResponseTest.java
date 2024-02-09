package com.distrimind.bouncycastle.asn1.cmc.test;

import com.distrimind.bouncycastle.asn1.ASN1Encodable;
import com.distrimind.bouncycastle.asn1.ASN1Integer;
import com.distrimind.bouncycastle.asn1.DERSequence;
import com.distrimind.bouncycastle.asn1.DERSet;
import com.distrimind.bouncycastle.asn1.DERUTF8String;
import com.distrimind.bouncycastle.asn1.cmc.BodyPartID;
import com.distrimind.bouncycastle.asn1.cmc.OtherMsg;
import com.distrimind.bouncycastle.asn1.cmc.PKIResponse;
import com.distrimind.bouncycastle.asn1.cmc.TaggedAttribute;
import com.distrimind.bouncycastle.asn1.cmc.TaggedContentInfo;
import com.distrimind.bouncycastle.asn1.cms.ContentInfo;
import com.distrimind.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import com.distrimind.bouncycastle.util.test.SimpleTest;


public class PKIResponseTest
    extends SimpleTest
{
    public static void main(String[] args)
    {
        runTest(new PKIResponseTest());
    }

    public String getName()
    {
        return "PKIResponseTest";
    }

    public void performTest()
        throws Exception
    {
        PKIResponse pkiResponse = PKIResponse.getInstance(new DERSequence(new ASN1Encodable[]{
            new DERSequence(new TaggedAttribute(new BodyPartID(10L), PKCSObjectIdentifiers.bagtypes, new DERSet())),
            new DERSequence(new TaggedContentInfo(new BodyPartID(12L), new ContentInfo(PKCSObjectIdentifiers.id_aa, new ASN1Integer(10L)))),
            new DERSequence(new OtherMsg(new BodyPartID(12), PKCSObjectIdentifiers.id_aa_msgSigDigest, new DERUTF8String("foo")))
        }));

        byte[] b = pkiResponse.getEncoded();

        PKIResponse pkiResponseResult = PKIResponse.getInstance(b);

        isEquals(pkiResponse, pkiResponseResult);

    }
}
