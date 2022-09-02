package com.distrimind.bouncycastle.cms.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;

import com.distrimind.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.distrimind.bouncycastle.asn1.DERSequence;
import com.distrimind.bouncycastle.asn1.x500.X500Name;
import com.distrimind.bouncycastle.asn1.x509.KeyPurposeId;
import com.distrimind.bouncycastle.cert.X509v3CertificateBuilder;
import com.distrimind.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import com.distrimind.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import com.distrimind.bouncycastle.jce.X509KeyUsage;
import com.distrimind.bouncycastle.operator.ContentSigner;
import com.distrimind.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import com.distrimind.bouncycastle.pqc.jcajce.spec.SPHINCS256KeyGenParameterSpec;

public class PQCTestUtil
{
    public static KeyPair makeKeyPair()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("SPHINCS256", "BCPQC");

        kpGen.initialize(new SPHINCS256KeyGenParameterSpec(), new SecureRandom());

        return kpGen.generateKeyPair();
    }

    public static X509Certificate makeCertificate(KeyPair subKP, String subDN, KeyPair issKP, String issDN)
        throws Exception
    {
        //
        // create base certificate - version 3
        //
        ContentSigner sigGen = new JcaContentSignerBuilder("SHA512withSPHINCS256").setProvider("BCPQC").build(issKP.getPrivate());

        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(new X500Name(issDN), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), new X500Name(subDN), subKP.getPublic())
            .addExtension(new ASN1ObjectIdentifier("2.5.29.15"), true,
                new X509KeyUsage(X509KeyUsage.digitalSignature))
            .addExtension(new ASN1ObjectIdentifier("2.5.29.37"), true,
                new DERSequence(KeyPurposeId.anyExtendedKeyUsage));

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certGen.build(sigGen));
    }
}
