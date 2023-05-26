package com.distrimind.bouncycastle.cert.test;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import com.distrimind.bouncycastle.asn1.bc.BCObjectIdentifiers;
import com.distrimind.bouncycastle.asn1.bc.ExternalValue;
import com.distrimind.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import com.distrimind.bouncycastle.asn1.x500.X500Name;
import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.asn1.x509.GeneralName;
import com.distrimind.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import com.distrimind.bouncycastle.cert.X509CertificateHolder;
import com.distrimind.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import com.distrimind.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import com.distrimind.bouncycastle.jcajce.ExternalPublicKey;
import com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider;
import com.distrimind.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import com.distrimind.bouncycastle.util.BigIntegers;
import com.distrimind.bouncycastle.util.test.SimpleTest;

public class ExternalKeyTest
    extends SimpleTest
{
    public String getName()
    {
        return "ExternalKey";
    }

    public void performTest()
        throws Exception
    {
        checkPublicKeyInfo();
        checkCertificate();
    }

    private void checkPublicKeyInfo()
        throws NoSuchAlgorithmException, IOException
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC");

        KeyPair kp = kpGen.generateKeyPair();

        byte[] keyDigest = MessageDigest.getInstance("SHA256").digest(kp.getPublic().getEncoded());

        PublicKey externalKey = new ExternalPublicKey(kp.getPublic(),
            new GeneralName(GeneralName.uniformResourceIdentifier, "http://localhost"),
            MessageDigest.getInstance("SHA256"));

        SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(externalKey.getEncoded());

        isEquals(BCObjectIdentifiers.external_value, info.getAlgorithm().getAlgorithm());

        ExternalValue extValue = ExternalValue.getInstance(info.parsePublicKey());

        isEquals(new GeneralName(GeneralName.uniformResourceIdentifier, "http://localhost"), extValue.getLocation());
        isEquals(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256), extValue.getHashAlg());
        isTrue(areEqual(keyDigest, extValue.getHashVal().getOctets()));
    }

    private void checkCertificate()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC");

        KeyPair kp = kpGen.generateKeyPair();

        ExternalPublicKey externalKey = new ExternalPublicKey(kp.getPublic(),
            new GeneralName(GeneralName.uniformResourceIdentifier, "https://localhost"),
            MessageDigest.getInstance("SHA256"));

        X500Name name = new X500Name("CN=Test");
        long time = System.currentTimeMillis();
        JcaX509v1CertificateBuilder certBldr = new JcaX509v1CertificateBuilder(
            name, BigIntegers.ONE, new Date(time - 5000), new Date(time + 50000), name, externalKey);

        X509CertificateHolder certHolder = certBldr.build(new JcaContentSignerBuilder("SHA256withECDSA").build(kp.getPrivate()));

        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new ExternalKeyTest());
    }
}
