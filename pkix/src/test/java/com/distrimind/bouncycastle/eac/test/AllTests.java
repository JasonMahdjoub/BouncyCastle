package com.distrimind.bouncycastle.eac.test;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import com.distrimind.bouncycastle.asn1.eac.CertificateHolderAuthorization;
import com.distrimind.bouncycastle.asn1.eac.CertificateHolderReference;
import com.distrimind.bouncycastle.asn1.eac.CertificationAuthorityReference;
import com.distrimind.bouncycastle.asn1.eac.EACObjectIdentifiers;
import com.distrimind.bouncycastle.asn1.eac.PackedDate;
import com.distrimind.bouncycastle.eac.EACCertificateBuilder;
import com.distrimind.bouncycastle.eac.EACCertificateHolder;
import com.distrimind.bouncycastle.eac.EACCertificateRequestHolder;
import com.distrimind.bouncycastle.eac.jcajce.JcaPublicKeyConverter;
import com.distrimind.bouncycastle.eac.operator.EACSignatureVerifier;
import com.distrimind.bouncycastle.eac.operator.EACSigner;
import com.distrimind.bouncycastle.eac.operator.jcajce.JcaEACSignatureVerifierBuilder;
import com.distrimind.bouncycastle.eac.operator.jcajce.JcaEACSignerBuilder;
import com.distrimind.bouncycastle.jce.ECNamedCurveTable;
import com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider;
import com.distrimind.bouncycastle.jce.spec.ECParameterSpec;
import com.distrimind.bouncycastle.test.PrintTestResult;
import com.distrimind.bouncycastle.util.Arrays;
import com.distrimind.bouncycastle.util.io.Streams;

public class AllTests
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    public void setUp()
    {
        if (Security.getProvider(BC) != null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testLoadCertificate() throws Exception
    {
        EACCertificateHolder certHolder = new EACCertificateHolder(getInput("Belgique CVCA-02032010.7816.cvcert"));

        PublicKey pubKey = new JcaPublicKeyConverter().setProvider(BC).getKey(certHolder.getPublicKeyDataObject());
        EACSignatureVerifier verifier = new JcaEACSignatureVerifierBuilder().build(certHolder.getPublicKeyDataObject().getUsage(), pubKey);

        if (!certHolder.isSignatureValid(verifier))
        {
            fail("signature test failed");
        }
    }

    private byte[] getInput(String name)
        throws IOException
    {
        return Streams.readAll(getClass().getResourceAsStream(name));
    }

    public void testLoadInvalidRequest() throws Exception
    {
        // this request contains invalid unsigned integers (see D 2.1.1)
        EACCertificateRequestHolder requestHolder = new EACCertificateRequestHolder(getInput("REQ_18102010.csr"));

        PublicKey pubKey = new JcaPublicKeyConverter().setProvider(BC).getKey(requestHolder.getPublicKeyDataObject());
        EACSignatureVerifier verifier = new JcaEACSignatureVerifierBuilder().build(requestHolder.getPublicKeyDataObject().getUsage(), pubKey);

        if (requestHolder.isInnerSignatureValid(verifier))
        {
            fail("signature test failed");
        }
    }

    public void testLoadCSR() throws Exception
    {
        // this request contains invalid unsigned integers (see D 2.1.1)
        byte[] input = getInput("UTIS00100072.csr");
   
        EACCertificateRequestHolder requestHolder = new EACCertificateRequestHolder(input);

        PublicKey pubKey = new JcaPublicKeyConverter().setProvider(BC).getKey(requestHolder.getPublicKeyDataObject());
        EACSignatureVerifier verifier = new JcaEACSignatureVerifierBuilder().build(requestHolder.getPublicKeyDataObject().getUsage(), pubKey);

        TestCase.assertTrue("signature test failed", requestHolder.isInnerSignatureValid(verifier));
        TestCase.assertTrue("comparison failed", Arrays.areEqual(input, requestHolder.toASN1Structure().getEncoded()));
    }

    public void testLoadRefCert() throws Exception
    {
        EACCertificateHolder certHolder = new EACCertificateHolder(getInput("at_cert_19a.cvcert"));


    }

    public void testGenerateEC()
        throws Exception
    {
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        KeyPair kp = generateECKeyPair(ecSpec);

        JcaEACSignerBuilder signerBuilder = new JcaEACSignerBuilder().setProvider(BC);

        EACSigner signer = signerBuilder.build("SHA256withECDSA", kp.getPrivate());

        int role = CertificateHolderAuthorization.CVCA;
        int rights = CertificateHolderAuthorization.RADG3 | CertificateHolderAuthorization.RADG4;

        EACCertificateBuilder certBuilder = new EACCertificateBuilder(
            new CertificationAuthorityReference("AU", "BC TEST", "12345"),
            new JcaPublicKeyConverter().getPublicKeyDataObject(signer.getUsageIdentifier(), kp.getPublic()),
            new CertificateHolderReference("AU", "BC TEST", "12345"),
            new CertificateHolderAuthorization(EACObjectIdentifiers.id_EAC_ePassport, role | rights),
            new PackedDate("110101"),
            new PackedDate("120101"));

        EACCertificateHolder certHolder = certBuilder.build(signer);

        EACSignatureVerifier verifier = new JcaEACSignatureVerifierBuilder().build(certHolder.getPublicKeyDataObject().getUsage(), kp.getPublic());

        if (!certHolder.isSignatureValid(verifier))
        {
            fail("first signature test failed");
        }

        PublicKey pubKey = new JcaPublicKeyConverter().setProvider(BC).getKey(certHolder.getPublicKeyDataObject());
        verifier = new JcaEACSignatureVerifierBuilder().build(certHolder.getPublicKeyDataObject().getUsage(), pubKey);

        if (!certHolder.isSignatureValid(verifier))
        {
            fail("second signature test failed");
        }
    }

    public void testGenerateRSA()
        throws Exception
    {
        KeyPair kp = generateRSAKeyPair();

        JcaEACSignerBuilder signerBuilder = new JcaEACSignerBuilder().setProvider(BC);

        EACSigner signer = signerBuilder.build("SHA256withRSA", kp.getPrivate());

        int role = CertificateHolderAuthorization.CVCA;
        int rights = CertificateHolderAuthorization.RADG3 | CertificateHolderAuthorization.RADG4;

        EACCertificateBuilder certBuilder = new EACCertificateBuilder(
            new CertificationAuthorityReference("AU", "BC TEST", "12345"),
            new JcaPublicKeyConverter().getPublicKeyDataObject(signer.getUsageIdentifier(), kp.getPublic()),
            new CertificateHolderReference("AU", "BC TEST", "12345"),
            new CertificateHolderAuthorization(EACObjectIdentifiers.id_EAC_ePassport, role | rights),
            new PackedDate("110101"),
            new PackedDate("120101"));

        EACCertificateHolder certHolder = certBuilder.build(signer);

        EACSignatureVerifier verifier = new JcaEACSignatureVerifierBuilder().build(certHolder.getPublicKeyDataObject().getUsage(), kp.getPublic());

        if (!certHolder.isSignatureValid(verifier))
        {
            fail("first signature test failed");
        }

        PublicKey pubKey = new JcaPublicKeyConverter().setProvider(BC).getKey(certHolder.getPublicKeyDataObject());
        verifier = new JcaEACSignatureVerifierBuilder().build(certHolder.getPublicKeyDataObject().getUsage(), pubKey);

        if (!certHolder.isSignatureValid(verifier))
        {
            fail("second signature test failed");
        }
    }

    private KeyPair generateECKeyPair(ECParameterSpec spec) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
    {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("ECDSA",BC);

        gen.initialize(spec, new SecureRandom());

        KeyPair generatedKeyPair = gen.generateKeyPair();
        return generatedKeyPair;
    }

    private KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
    {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA",BC);

        gen.initialize(1024, new SecureRandom());

        KeyPair generatedKeyPair = gen.generateKeyPair();
        return generatedKeyPair;
    }

    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
        throws Exception
    {
        TestSuite suite = new TestSuite("EAC tests");

        suite.addTestSuite(AllTests.class);

        return new EACTestSetup(suite);
    }
}
