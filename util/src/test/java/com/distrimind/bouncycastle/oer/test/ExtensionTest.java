package com.distrimind.bouncycastle.oer.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import com.distrimind.bouncycastle.asn1.ASN1Encodable;
import com.distrimind.bouncycastle.asn1.ASN1Integer;
import com.distrimind.bouncycastle.oer.OERInputStream;
import com.distrimind.bouncycastle.oer.OEROutputStream;
import com.distrimind.bouncycastle.oer.its.etsi103097.extension.EtsiTs102941CrlRequest;
import com.distrimind.bouncycastle.oer.its.etsi103097.extension.EtsiTs102941DeltaCtlRequest;
import com.distrimind.bouncycastle.oer.its.etsi103097.extension.Extension;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId8;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.basetypes.Time32;
import com.distrimind.bouncycastle.oer.its.template.etsi103097.extension.EtsiTs103097ExtensionModule;
import com.distrimind.bouncycastle.util.encoders.Hex;
import com.distrimind.bouncycastle.util.test.SimpleTest;
import com.distrimind.bouncycastle.util.test.TestResult;

public class ExtensionTest
    extends SimpleTest
{

    @Override
    public String getName()
    {
        return "OER Encoding of Extension";
    }


    @Override
    public void performTest()
        throws Exception
    {
        exerciseEtsiTs102941CrlRequestId();
        exerciseEtsiTs102941DeltaCtlRequestId();
    }

    private void exerciseEtsiTs102941DeltaCtlRequestId()
        throws Exception
    {
        ASN1Integer ctlSequence = new ASN1Integer(10);

        Extension extension = new Extension(
            Extension.etsiTs102941DeltaCtlRequestId,
            EtsiTs102941DeltaCtlRequest.builder()
                .setIssuerId(new HashedId8(Hex.decode("0001020304050608")))
                .setLastKnownCtlSequence(ctlSequence).createEtsiTs102941CtlRequest());

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        OEROutputStream oos = new OEROutputStream(bos);
        oos.write(extension, EtsiTs103097ExtensionModule.Extension.build());

        ByteArrayInputStream bin = new ByteArrayInputStream(bos.toByteArray());
        OERInputStream oin = new OERInputStream(bin);

        ASN1Encodable output = oin.parse(EtsiTs103097ExtensionModule.Extension.build());

        Extension retruned = Extension.getInstance(output);

        isEquals("type id", retruned.getId(), Extension.etsiTs102941DeltaCtlRequestId);

        EtsiTs102941DeltaCtlRequest body = EtsiTs102941DeltaCtlRequest.getInstance(retruned.getContent());
        isTrue("Issuer ID",areEqual(body.getIssuerId().getHashBytes(), Hex.decode("0001020304050608")));
        isEquals(body.getLastKnownCtlSequence(), ctlSequence);
    }

    private void exerciseEtsiTs102941CrlRequestId()
        throws Exception
    {
        Time32 time = Time32.now();

        Extension extension = new Extension(
            Extension.etsiTs102941CrlRequestId,
            EtsiTs102941CrlRequest.builder()
                .setIssuerId(new HashedId8(Hex.decode("0001020304050607")))
                .setLastKnownUpdate(time).createEtsiTs102941CrlRequest());

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        OEROutputStream oos = new OEROutputStream(bos);
        oos.write(extension, EtsiTs103097ExtensionModule.Extension.build());

        ByteArrayInputStream bin = new ByteArrayInputStream(bos.toByteArray());
        OERInputStream oin = new OERInputStream(bin);

        ASN1Encodable output = oin.parse(EtsiTs103097ExtensionModule.Extension.build());

        Extension retruned = Extension.getInstance(output);

        isEquals("type id", retruned.getId(), Extension.etsiTs102941CrlRequestId);

        EtsiTs102941CrlRequest body = EtsiTs102941CrlRequest.getInstance(retruned.getContent());
        isTrue("Issuer id",areEqual(body.getIssuerId().getHashBytes(), Hex.decode("0001020304050607")));
        isEquals(body.getLastKnownUpdate(), time);
    }

    public static void main(
        String[] args)
    {
        ExtensionTest test = new ExtensionTest();
        TestResult result = test.perform();

        System.out.println(result);
        if (result.getException() != null)
        {
            result.getException().printStackTrace();
        }
    }
}
