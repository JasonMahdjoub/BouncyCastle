package com.distrimind.bouncycastle.asn1.cmc.test;

import com.distrimind.bouncycastle.asn1.ASN1Integer;
import com.distrimind.bouncycastle.asn1.DERSequence;
import com.distrimind.bouncycastle.asn1.DERSet;
import com.distrimind.bouncycastle.asn1.cmc.BodyPartID;
import com.distrimind.bouncycastle.asn1.cmc.CertificationRequest;
import com.distrimind.bouncycastle.asn1.cmc.OtherMsg;
import com.distrimind.bouncycastle.asn1.cmc.PKIData;
import com.distrimind.bouncycastle.asn1.cmc.TaggedAttribute;
import com.distrimind.bouncycastle.asn1.cmc.TaggedCertificationRequest;
import com.distrimind.bouncycastle.asn1.cmc.TaggedContentInfo;
import com.distrimind.bouncycastle.asn1.cmc.TaggedRequest;
import com.distrimind.bouncycastle.asn1.cms.ContentInfo;
import com.distrimind.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import com.distrimind.bouncycastle.util.Arrays;
import com.distrimind.bouncycastle.util.encoders.Base64;
import com.distrimind.bouncycastle.util.test.SimpleTest;


public class PKIDataTest
    extends SimpleTest
{
    public static void main(String[] args)
    {
        runTest(new PKIDataTest());
    }

    public String getName()
    {
        return "PKIDataTest";
    }

    public void performTest()
        throws Exception
    {

        byte[] req1 = Base64.decode(
            "MIHoMIGTAgEAMC4xDjAMBgNVBAMTBVRlc3QyMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNF"
                + "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALlEt31Tzt2MlcOljvacJgzQVhmlMoqAOgqJ9Pgd3Gux"
                + "Z7/WcIlgW4QCB7WZT21O1YoghwBhPDMcNGrHei9kHQkCAwEAAaAAMA0GCSqGSIb3DQEBBQUAA0EA"
                + "NDEI4ecNtJ3uHwGGlitNFq9WxcoZ0djbQJ5hABMotav6gtqlrwKXY2evaIrsNwkJtNdwwH18aQDU"
                + "KCjOuBL38Q==");


        PKIData pkiData = new PKIData(
            new TaggedAttribute[]{new TaggedAttribute(new BodyPartID(10L), PKCSObjectIdentifiers.id_aa, new DERSet())},
            new TaggedRequest[]{new TaggedRequest(new TaggedCertificationRequest(new BodyPartID(10L), CertificationRequest.getInstance(req1)))},
            new TaggedContentInfo[]{new TaggedContentInfo(new BodyPartID(10L), new ContentInfo(PKCSObjectIdentifiers.id_aa_ets_commitmentType, new ASN1Integer(10L)))},
            new OtherMsg[]{new OtherMsg(new BodyPartID(10L), PKCSObjectIdentifiers.pkcs_9, new ASN1Integer(10L))});


        byte[] b = pkiData.getEncoded();

        PKIData pkiDataResult = PKIData.getInstance(b);

        isTrue("controlSequence", Arrays.areEqual(pkiData.getControlSequence(), pkiDataResult.getControlSequence()));
        isTrue("reqSequence", Arrays.areEqual(pkiData.getReqSequence(), pkiDataResult.getReqSequence()));
        isTrue("cmsSequence", Arrays.areEqual(pkiData.getCmsSequence(), pkiDataResult.getCmsSequence()));
        isTrue("otherMsgSequence", Arrays.areEqual(pkiData.getOtherMsgSequence(), pkiDataResult.getOtherMsgSequence()));

        try
        {
            PKIData.getInstance(new DERSequence());
            fail("Sequence must be 4.");
        }
        catch (Throwable t)
        {
            isEquals("Exception type", t.getClass(), IllegalArgumentException.class);
        }

    }
}
