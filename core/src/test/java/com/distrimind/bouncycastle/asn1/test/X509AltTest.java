package com.distrimind.bouncycastle.asn1.test;

import com.distrimind.bouncycastle.asn1.DERBitString;
import com.distrimind.bouncycastle.asn1.DERNull;
import com.distrimind.bouncycastle.asn1.DERTaggedObject;
import com.distrimind.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.asn1.x509.AltSignatureAlgorithm;
import com.distrimind.bouncycastle.asn1.x509.AltSignatureValue;
import com.distrimind.bouncycastle.asn1.x509.Extension;
import com.distrimind.bouncycastle.asn1.x509.Extensions;
import com.distrimind.bouncycastle.asn1.x509.ExtensionsGenerator;
import com.distrimind.bouncycastle.asn1.x509.SubjectAltPublicKeyInfo;
import com.distrimind.bouncycastle.util.encoders.Hex;
import com.distrimind.bouncycastle.util.test.SimpleTest;

public class X509AltTest
    extends SimpleTest
{
    public String getName()
    {
        return "X509Alt";
    }

    public void performTest()
        throws Exception
    {
        SubjectAltPublicKeyInfo subAlt = new SubjectAltPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE), new DERBitString(Hex.decode("0102030405060708090807060504030201")));
        AltSignatureValue sigValAlt = new AltSignatureValue(Hex.decode("0102030405060708090807060504030201"));

        AltSignatureAlgorithm sigAlgAlt = new AltSignatureAlgorithm(new AlgorithmIdentifier(PKCSObjectIdentifiers.md5WithRSAEncryption, DERNull.INSTANCE));
        AltSignatureAlgorithm sigAlgAlt2 = new AltSignatureAlgorithm(PKCSObjectIdentifiers.md5WithRSAEncryption, DERNull.INSTANCE);


        isEquals(sigAlgAlt, sigAlgAlt2);

        ExtensionsGenerator extGen = new ExtensionsGenerator();

        extGen.addExtension(Extension.subjectAltPublicKeyInfo, false, subAlt);

        extGen.addExtension(Extension.altSignatureAlgorithm, false, sigAlgAlt);

        extGen.addExtension(Extension.altSignatureValue, false, sigValAlt);

        Extensions exts = extGen.generate();

        isEquals(subAlt, SubjectAltPublicKeyInfo.fromExtensions(exts));

        isEquals(sigAlgAlt, AltSignatureAlgorithm.fromExtensions(exts));

        isEquals(sigValAlt, AltSignatureValue.fromExtensions(exts));

        isEquals(subAlt, SubjectAltPublicKeyInfo.getInstance(subAlt.getEncoded()));

        isEquals(sigAlgAlt, AltSignatureAlgorithm.getInstance(sigAlgAlt.getEncoded()));

        isEquals(sigValAlt, AltSignatureValue.getInstance(sigValAlt.getEncoded()));

        isEquals(subAlt, SubjectAltPublicKeyInfo.getInstance(new DERTaggedObject(1, subAlt), true));

        isEquals(sigAlgAlt, AltSignatureAlgorithm.getInstance(new DERTaggedObject(1, sigAlgAlt), true));

        isEquals(sigValAlt, AltSignatureValue.getInstance(new DERTaggedObject(1, sigValAlt), true));
    }

    public static void main(
        String[]    args)
    {
        runTest(new X509AltTest());
    }
}
