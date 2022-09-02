package com.distrimind.bouncycastle.tsp.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import junit.framework.TestCase;
import com.distrimind.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.distrimind.bouncycastle.asn1.cms.AttributeTable;
import com.distrimind.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import com.distrimind.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import com.distrimind.bouncycastle.asn1.x500.X500Name;
import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.asn1.x509.ExtendedKeyUsage;
import com.distrimind.bouncycastle.asn1.x509.Extension;
import com.distrimind.bouncycastle.asn1.x509.KeyPurposeId;
import com.distrimind.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import com.distrimind.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import com.distrimind.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import com.distrimind.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider;
import com.distrimind.bouncycastle.operator.ContentSigner;
import com.distrimind.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import com.distrimind.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import com.distrimind.bouncycastle.tsp.TSPAlgorithms;
import com.distrimind.bouncycastle.tsp.TimeStampRequest;
import com.distrimind.bouncycastle.tsp.TimeStampRequestGenerator;
import com.distrimind.bouncycastle.tsp.TimeStampResponse;
import com.distrimind.bouncycastle.tsp.TimeStampResponseGenerator;
import com.distrimind.bouncycastle.tsp.TimeStampToken;
import com.distrimind.bouncycastle.tsp.TimeStampTokenGenerator;

public class PQCTSPTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    public void setUp()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void testLMS()
        throws Exception
    {
        //
        // set up the keys
        //
        PrivateKey privKey;
        PublicKey pubKey;

        try
        {
            KeyPairGenerator g = KeyPairGenerator.getInstance("LMS", BC);

            KeyPair p = g.generateKeyPair();

            privKey = p.getPrivate();
            pubKey = p.getPublic();
        }
        catch (Exception e)
        {
            fail("error setting up keys - " + e);
            return;
        }

        //
        // extensions
        //

        //
        // create the certificate - version 1
        //

        ContentSigner sigGen = new JcaContentSignerBuilder("LMS")
            .setProvider(BC).build(privKey);
        JcaX509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
            new X500Name("CN=Test"),
            BigInteger.valueOf(1),
            new Date(System.currentTimeMillis() - 50000),
            new Date(System.currentTimeMillis() + 50000),
            new X500Name("CN=Test"),
            pubKey);

        certGen.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));

        X509Certificate cert = new JcaX509CertificateConverter()
            .setProvider("BC").getCertificate(certGen.build(sigGen));

        ContentSigner signer = new JcaContentSignerBuilder("LMS").setProvider(BC).build(privKey);

        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
            new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build())
                .setContentDigest(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256))
                .build(signer, cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

        // tsTokenGen.addCertificates(certs);

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        TimeStampRequest request = reqGen.generate(TSPAlgorithms.SM3, new byte[32], BigInteger.valueOf(100));

        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);

        TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), new Date());

        tsResp = new TimeStampResponse(tsResp.getEncoded());

        TimeStampToken tsToken = tsResp.getTimeStampToken();

        tsToken.validate(new JcaSignerInfoVerifierBuilder(new JcaDigestCalculatorProviderBuilder().build())
            .setProvider(BC).build(cert));

        AttributeTable table = tsToken.getSignedAttributes();

        assertNotNull("no signingCertificate attribute found", table.get(PKCSObjectIdentifiers.id_aa_signingCertificate));
    }

    public void testSPHINCSPlus()
        throws Exception
    {
        //
        // set up the keys
        //
        PrivateKey privKey;
        PublicKey pubKey;

        try
        {
            KeyPairGenerator g = KeyPairGenerator.getInstance("SPHINCS+", BC);

            KeyPair p = g.generateKeyPair();

            privKey = p.getPrivate();
            pubKey = p.getPublic();
        }
        catch (Exception e)
        {
            fail("error setting up keys - " + e);
            return;
        }

        //
        // extensions
        //

        //
        // create the certificate - version 1
        //

        ContentSigner sigGen = new JcaContentSignerBuilder("SPHINCS+")
            .setProvider(BC).build(privKey);
        JcaX509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
            new X500Name("CN=Test"),
            BigInteger.valueOf(1),
            new Date(System.currentTimeMillis() - 50000),
            new Date(System.currentTimeMillis() + 50000),
            new X500Name("CN=Test"),
            pubKey);

        certGen.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));

        X509Certificate cert = new JcaX509CertificateConverter()
            .setProvider("BC").getCertificate(certGen.build(sigGen));

        ContentSigner signer = new JcaContentSignerBuilder("SPHINCS+").setProvider(BC).build(privKey);

        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
            new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build())
                .setContentDigest(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256))
                .build(signer, cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

        // tsTokenGen.addCertificates(certs);

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        TimeStampRequest request = reqGen.generate(TSPAlgorithms.SM3, new byte[32], BigInteger.valueOf(100));

        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);

        TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), new Date());

        tsResp = new TimeStampResponse(tsResp.getEncoded());

        TimeStampToken tsToken = tsResp.getTimeStampToken();

        tsToken.validate(new JcaSignerInfoVerifierBuilder(new JcaDigestCalculatorProviderBuilder().build())
            .setProvider(BC).build(cert));

        AttributeTable table = tsToken.getSignedAttributes();

        assertNotNull("no signingCertificate attribute found", table.get(PKCSObjectIdentifiers.id_aa_signingCertificate));
    }
}
