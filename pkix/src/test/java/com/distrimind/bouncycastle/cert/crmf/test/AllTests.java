package com.distrimind.bouncycastle.cert.crmf.test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.util.Date;

import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.security.auth.x500.X500Principal;

import com.distrimind.bouncycastle.asn1.*;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import com.distrimind.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import com.distrimind.bouncycastle.asn1.crmf.*;
import com.distrimind.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import com.distrimind.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import com.distrimind.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import com.distrimind.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import com.distrimind.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import com.distrimind.bouncycastle.asn1.x500.X500Name;
import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.asn1.x509.GeneralName;
import com.distrimind.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import com.distrimind.bouncycastle.cert.X509CertificateHolder;
import com.distrimind.bouncycastle.cert.X509v1CertificateBuilder;
import com.distrimind.bouncycastle.cert.crmf.CRMFException;
import com.distrimind.bouncycastle.cert.crmf.EncryptedValueBuilder;
import com.distrimind.bouncycastle.cert.crmf.EncryptedValuePadder;
import com.distrimind.bouncycastle.cert.crmf.EncryptedValueParser;
import com.distrimind.bouncycastle.cert.crmf.PKIArchiveControl;
import com.distrimind.bouncycastle.cert.crmf.PKMACBuilder;
import com.distrimind.bouncycastle.cert.crmf.ValueDecryptorGenerator;
import com.distrimind.bouncycastle.cert.crmf.bc.BcCRMFEncryptorBuilder;
import com.distrimind.bouncycastle.cert.crmf.bc.BcEncryptedValueBuilder;
import com.distrimind.bouncycastle.cert.crmf.bc.BcFixedLengthMGF1Padder;
import com.distrimind.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessage;
import com.distrimind.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessageBuilder;
import com.distrimind.bouncycastle.cert.crmf.jcajce.JcaEncryptedValueBuilder;
import com.distrimind.bouncycastle.cert.crmf.jcajce.JcaPKIArchiveControlBuilder;
import com.distrimind.bouncycastle.cert.crmf.jcajce.JceAsymmetricValueDecryptorGenerator;
import com.distrimind.bouncycastle.cert.crmf.jcajce.JceCRMFEncryptorBuilder;
import com.distrimind.bouncycastle.cert.crmf.jcajce.JcePKMACValuesCalculator;
import com.distrimind.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import com.distrimind.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import com.distrimind.bouncycastle.cms.CMSAlgorithm;
import com.distrimind.bouncycastle.cms.CMSEnvelopedData;
import com.distrimind.bouncycastle.cms.CMSEnvelopedDataGenerator;
import com.distrimind.bouncycastle.cms.CMSException;
import com.distrimind.bouncycastle.cms.Recipient;
import com.distrimind.bouncycastle.cms.RecipientId;
import com.distrimind.bouncycastle.cms.RecipientInformation;
import com.distrimind.bouncycastle.cms.RecipientInformationStore;
import com.distrimind.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import com.distrimind.bouncycastle.cms.jcajce.JceKeyAgreeEnvelopedRecipient;
import com.distrimind.bouncycastle.cms.jcajce.JceKeyAgreeRecipientId;
import com.distrimind.bouncycastle.cms.jcajce.JceKeyAgreeRecipientInfoGenerator;
import com.distrimind.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import com.distrimind.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import com.distrimind.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import com.distrimind.bouncycastle.crypto.util.PrivateKeyFactory;
import com.distrimind.bouncycastle.crypto.util.PublicKeyFactory;
import com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider;
import com.distrimind.bouncycastle.operator.OperatorCreationException;
import com.distrimind.bouncycastle.operator.OutputEncryptor;
import com.distrimind.bouncycastle.operator.bc.BcRSAAsymmetricKeyWrapper;
import com.distrimind.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import com.distrimind.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import com.distrimind.bouncycastle.operator.jcajce.JceAsymmetricKeyWrapper;
import com.distrimind.bouncycastle.util.Arrays;

public class AllTests
    extends TestCase
{
    private static final byte[] TEST_DATA = "Hello world!".getBytes();
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final String PASSPHRASE = "hello world";

    /*
     *
     *  INFRASTRUCTURE
     *
     */

    public AllTests(String name)
    {
        super(name);
    }

    public static void main(String args[])
    {
        junit.textui.TestRunner.run(AllTests.class);
    }

    public static Test suite()
    {
        return new TestSuite(AllTests.class);
    }

    public void setUp()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void tearDown()
    {

    }

    public void testBasicMessage()
        throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();

        JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigInteger.ONE);

        certReqBuild.setSubject(new X500Principal("CN=Test"))
                    .setPublicKey(kp.getPublic())
                    .setProofOfPossessionSigningKeySigner(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(kp.getPrivate()));

        JcaCertificateRequestMessage certReqMsg = new JcaCertificateRequestMessage(certReqBuild.build()).setProvider(BC);


        POPOSigningKey popoSign = POPOSigningKey.getInstance(certReqMsg.toASN1Structure().getPop().getObject());

        Signature sig = Signature.getInstance("SHA1withRSA", "BC");

        sig.initVerify(certReqMsg.getPublicKey());

        // this is the original approach in RFC 2511 - there's a typo in RFC 4211, the standard contradicts itself
        // between 4.1. 3 and then a couple of paragraphs later.
        sig.update(certReqMsg.toASN1Structure().getCertReq().getEncoded(ASN1Encoding.DER));

        TestCase.assertTrue(sig.verify(popoSign.getSignature().getOctets()));

        TestCase.assertEquals(new X500Principal("CN=Test"), certReqMsg.getSubjectX500Principal());
        TestCase.assertEquals(kp.getPublic(), certReqMsg.getPublicKey());
    }

    public void testBasicMessageWithRegInfo()
            throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();

        AttributeTypeAndValue regInfoATaV = new AttributeTypeAndValue(
                CMPObjectIdentifiers.regInfo_utf8Pairs,
                new DERUTF8String("CertType?Server%"));
        AttributeTypeAndValue[] atavArr = new AttributeTypeAndValue[1];
        atavArr[0] = regInfoATaV;

        JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigInteger.ONE);

        certReqBuild.setSubject(new X500Principal("CN=Test"))
                .setPublicKey(kp.getPublic())
                .setRegInfo(atavArr)
                .setProofOfPossessionSigningKeySigner(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(kp.getPrivate()));

        JcaCertificateRequestMessage certReqMsg = new JcaCertificateRequestMessage(certReqBuild.build()).setProvider(BC);


        POPOSigningKey popoSign = POPOSigningKey.getInstance(certReqMsg.toASN1Structure().getPop().getObject());

        Signature sig = Signature.getInstance("SHA1withRSA", "BC");

        sig.initVerify(certReqMsg.getPublicKey());

        // this is the original approach in RFC 2511 - there's a typo in RFC 4211, the standard contradicts itself
        // between 4.1. 3 and then a couple of paragraphs later.
        sig.update(certReqMsg.toASN1Structure().getCertReq().getEncoded(ASN1Encoding.DER));

        TestCase.assertTrue(sig.verify(popoSign.getSignature().getOctets()));

        TestCase.assertEquals(new X500Principal("CN=Test"), certReqMsg.getSubjectX500Principal());
        TestCase.assertEquals(kp.getPublic(), certReqMsg.getPublicKey());

        CertReqMsg certReqMsgASN1 = certReqMsg.toASN1Structure();
        TestCase.assertEquals(1, certReqMsgASN1.getRegInfo().length);
        TestCase.assertEquals(atavArr[0], certReqMsgASN1.getRegInfo()[0]);
    }

    public void testBasicMessageWithArchiveControl()
        throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();
        X509Certificate cert = makeV1Certificate(kp, "CN=Test", kp, "CN=Test");

        JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigInteger.ONE);

        certReqBuild.setSubject(new X500Principal("CN=Test"))
                    .setPublicKey(kp.getPublic());

        certReqBuild.addControl(new JcaPKIArchiveControlBuilder(kp.getPrivate(), new X500Principal("CN=Test"))
            .addRecipientGenerator(new JceKeyTransRecipientInfoGenerator(cert).setProvider(BC))
            .build(new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier(CMSEnvelopedDataGenerator.AES128_CBC)).setProvider(BC).build()));

        JcaCertificateRequestMessage certReqMsg = new JcaCertificateRequestMessage(certReqBuild.build()).setProvider(BC);

        TestCase.assertEquals(new X500Principal("CN=Test"), certReqMsg.getSubjectX500Principal());
        TestCase.assertEquals(kp.getPublic(), certReqMsg.getPublicKey());

        checkCertReqMsgWithArchiveControl(kp, cert, certReqMsg);
        checkCertReqMsgWithArchiveControl(kp, cert, new JcaCertificateRequestMessage(certReqMsg.getEncoded()));
    }

    public void testECBasicMessageWithArchiveControl()
        throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("EC", BC);

        kGen.initialize(256);

        KeyPair clientKp = kGen.generateKeyPair();
        KeyPair serverKp = kGen.generateKeyPair();
        X509Certificate serverCert = makeV1Certificate(serverKp, "CN=Test Server", serverKp, "CN=Test Server");

        JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigInteger.ONE);

        certReqBuild.setSubject(new X500Principal("CN=Test"))
                    .setPublicKey(clientKp.getPublic());

        certReqBuild.addControl(new JcaPKIArchiveControlBuilder(clientKp.getPrivate(), new X500Principal("CN=Test"))
            .addRecipientGenerator(new JceKeyAgreeRecipientInfoGenerator(
                        CMSAlgorithm.ECCDH_SHA256KDF,
                        clientKp.getPrivate(), serverKp.getPublic(),
                        CMSAlgorithm.AES256_WRAP)
                        .addRecipient(serverCert)
                        .setProvider(BC))
            .build(new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier(CMSEnvelopedDataGenerator.AES128_CBC)).setProvider(BC).build()));

        JcaCertificateRequestMessage certReqMsg = new JcaCertificateRequestMessage(certReqBuild.build()).setProvider(BC);

        TestCase.assertEquals(new X500Principal("CN=Test"), certReqMsg.getSubjectX500Principal());
        TestCase.assertEquals(clientKp.getPublic(), certReqMsg.getPublicKey());

        checkCertReqMsgWithArchiveControl(clientKp, serverCert, certReqMsg);
        checkCertReqMsgWithArchiveControl(clientKp, serverCert, new JcaCertificateRequestMessage(certReqMsg.getEncoded()));
    }

    private void checkCertReqMsgWithArchiveControl(KeyPair kp, X509Certificate cert, JcaCertificateRequestMessage certReqMsg)
        throws CRMFException, CMSException, IOException
    {
        PKIArchiveControl archiveControl = (PKIArchiveControl)certReqMsg.getControl(CRMFObjectIdentifiers.id_regCtrl_pkiArchiveOptions);

        TestCase.assertEquals(PKIArchiveControl.encryptedPrivKey, archiveControl.getArchiveType());

        TestCase.assertTrue(archiveControl.isEnvelopedData());

        CMSEnvelopedData envelopedData = archiveControl.getEnvelopedData();

        RecipientInformationStore recips = envelopedData.getRecipientInfos();

        RecipientId recipientId = new JceKeyTransRecipientId(cert);

        RecipientInformation recipientInformation = recips.get(recipientId);

        Recipient recipient;
        if (recipientInformation == null)
        {
            recipientId = new JceKeyAgreeRecipientId(cert);
            recipientInformation = recips.get(recipientId);
            recipient = new JceKeyAgreeEnvelopedRecipient(kp.getPrivate()).setProvider(BC);
            TestCase.assertEquals(CMSAlgorithm.ECCDH_SHA256KDF, recipientInformation.getKeyEncryptionAlgorithm().getAlgorithm());
        }
        else
        {
            recipient = new JceKeyTransEnvelopedRecipient(kp.getPrivate()).setProvider(BC);
            TestCase.assertEquals(PKCSObjectIdentifiers.rsaEncryption, recipientInformation.getKeyEncryptionAlgorithm().getAlgorithm());
        }

        TestCase.assertNotNull(recipientInformation);

        EncKeyWithID encKeyWithID = EncKeyWithID.getInstance(recipientInformation.getContent(recipient));

        TestCase.assertTrue(encKeyWithID.hasIdentifier());
        TestCase.assertFalse(encKeyWithID.isIdentifierUTF8String());

        TestCase.assertEquals(new GeneralName(X500Name.getInstance(new X500Principal("CN=Test").getEncoded())), encKeyWithID.getIdentifier());
        TestCase.assertTrue(Arrays.areEqual(kp.getPrivate().getEncoded(), encKeyWithID.getPrivateKey().getEncoded()));
    }

    public void testProofOfPossessionWithoutSender()
        throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();
        X509Certificate cert = makeV1Certificate(kp, "CN=Test", kp, "CN=Test");

        JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigInteger.ONE);

        certReqBuild.setPublicKey(kp.getPublic())
                    .setAuthInfoPKMAC(new PKMACBuilder(new JcePKMACValuesCalculator()), "fred".toCharArray())
                    .setProofOfPossessionSigningKeySigner(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(kp.getPrivate()));

        certReqBuild.addControl(new JcaPKIArchiveControlBuilder(kp.getPrivate(), new X500Principal("CN=test"))
            .addRecipientGenerator(new JceKeyTransRecipientInfoGenerator(cert).setProvider(BC))
            .build(new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier(CMSEnvelopedDataGenerator.AES128_CBC)).setProvider(BC).build()));

        JcaCertificateRequestMessage certReqMsg = new JcaCertificateRequestMessage(certReqBuild.build().getEncoded()).setProvider(BC);

        // check that internal check on popo signing is working okay
        try
        {
            certReqMsg.isValidSigningKeyPOP(new JcaContentVerifierProviderBuilder().setProvider(BC).build(kp.getPublic()));
            TestCase.fail("IllegalStateException not thrown");
        }
        catch (IllegalStateException e)
        {
            // ignore
        }

        TestCase.assertTrue(certReqMsg.isValidSigningKeyPOP(new JcaContentVerifierProviderBuilder().setProvider(BC).build(kp.getPublic()), new PKMACBuilder(new JcePKMACValuesCalculator().setProvider(BC)), "fred".toCharArray()));

        TestCase.assertEquals(kp.getPublic(), certReqMsg.getPublicKey());

        certReqMsg = new JcaCertificateRequestMessage(certReqBuild.build()).setProvider(BC);

                // check that internal check on popo signing is working okay
        try
        {
            certReqMsg.isValidSigningKeyPOP(new JcaContentVerifierProviderBuilder().setProvider(BC).build(kp.getPublic()));
            TestCase.fail("IllegalStateException not thrown");
        }
        catch (IllegalStateException e)
        {
            // ignore
        }

        TestCase.assertTrue(certReqMsg.isValidSigningKeyPOP(new JcaContentVerifierProviderBuilder().setProvider(BC).build(kp.getPublic()), new PKMACBuilder(new JcePKMACValuesCalculator().setProvider(BC)), "fred".toCharArray()));

        TestCase.assertEquals(kp.getPublic(), certReqMsg.getPublicKey());
    }

    public void testEncryptedValueWithKey()
        throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();

        JcaEncryptedValueBuilder build = new JcaEncryptedValueBuilder(new JceAsymmetricKeyWrapper(kp.getPublic()).setProvider(BC), new JceCRMFEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BC).build());

        EncryptedValue value = build.build(kp.getPrivate());

        ValueDecryptorGenerator decGen = new JceAsymmetricValueDecryptorGenerator(kp.getPrivate()).setProvider(BC);

        EncryptedValueParser  parser = new EncryptedValueParser(value);

        PrivateKeyInfo privInfo = parser.readPrivateKeyInfo(decGen);

        TestCase.assertEquals(privInfo.getPrivateKeyAlgorithm(), parser.getIntendedAlg());

        TestCase.assertTrue(Arrays.areEqual(privInfo.getEncoded(), kp.getPrivate().getEncoded()));
    }

    public void testBcEncryptedValueWithKey()
        throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();

        BcEncryptedValueBuilder build = new BcEncryptedValueBuilder(new BcRSAAsymmetricKeyWrapper(
            new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE),
            PublicKeyFactory.createKey(SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded()))),
            new BcCRMFEncryptorBuilder(CMSAlgorithm.AES128_CBC).build());

        EncryptedValue value = build.build(
            PrivateKeyFactory.createKey(PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded())));

        ValueDecryptorGenerator decGen = new JceAsymmetricValueDecryptorGenerator(kp.getPrivate()).setProvider(BC);

        EncryptedValueParser  parser = new EncryptedValueParser(value);

        PrivateKeyInfo privInfo = parser.readPrivateKeyInfo(decGen);

        TestCase.assertEquals(privInfo.getPrivateKeyAlgorithm(), parser.getIntendedAlg());

        TestCase.assertTrue(Arrays.areEqual(privInfo.getEncoded(), kp.getPrivate().getEncoded()));
    }

    public void testProofOfPossessionWithSender()
        throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();
        X509Certificate cert = makeV1Certificate(kp, "CN=Test", kp, "CN=Test");

        JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigInteger.ONE);

        certReqBuild.setPublicKey(kp.getPublic())
                    .setAuthInfoSender(new X500Principal("CN=Test"))
                    .setProofOfPossessionSigningKeySigner(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(kp.getPrivate()));

        certReqBuild.addControl(new JcaPKIArchiveControlBuilder(kp.getPrivate(), new X500Principal("CN=test"))
                                      .addRecipientGenerator(new JceKeyTransRecipientInfoGenerator(cert).setProvider(BC))
                                      .build(new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier(CMSEnvelopedDataGenerator.AES128_CBC)).setProvider(BC).build()));

        JcaCertificateRequestMessage certReqMsg = new JcaCertificateRequestMessage(certReqBuild.build().getEncoded());

        // check that internal check on popo signing is working okay
        try
        {
            certReqMsg.isValidSigningKeyPOP(new JcaContentVerifierProviderBuilder().setProvider(BC).build(kp.getPublic()), new PKMACBuilder(new JcePKMACValuesCalculator().setProvider(BC)), "fred".toCharArray());

            fail("IllegalStateException not thrown");
        }
        catch (IllegalStateException e)
        {
            // ignore
        }


        assertTrue(certReqMsg.isValidSigningKeyPOP(new JcaContentVerifierProviderBuilder().setProvider(BC).build(kp.getPublic())));

        assertEquals(kp.getPublic(), certReqMsg.getPublicKey());
    }

    public void testProofOfPossessionWithTemplate()
        throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();
        X509Certificate cert = makeV1Certificate(kp, "CN=Test", kp, "CN=Test");

        JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigInteger.ONE);

        certReqBuild.setPublicKey(kp.getPublic())
                    .setSubject(new X500Principal("CN=Test"))
                    .setAuthInfoSender(new X500Principal("CN=Test"))
                    .setProofOfPossessionSigningKeySigner(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(kp.getPrivate()));

        certReqBuild.addControl(new JcaPKIArchiveControlBuilder(kp.getPrivate(), new X500Principal("CN=test"))
                                      .addRecipientGenerator(new JceKeyTransRecipientInfoGenerator(cert).setProvider(BC))
                                      .build(new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier(CMSEnvelopedDataGenerator.AES128_CBC)).setProvider(BC).build()));

        JcaCertificateRequestMessage certReqMsg = new JcaCertificateRequestMessage(certReqBuild.build().getEncoded());

        assertTrue(certReqMsg.isValidSigningKeyPOP(new JcaContentVerifierProviderBuilder().setProvider(BC).build(kp.getPublic())));

        assertEquals(kp.getPublic(), certReqMsg.getPublicKey());
    }

    public void testKeySizes()
        throws Exception
    {
        verifyKeySize(NISTObjectIdentifiers.id_aes128_CBC, 128);
        verifyKeySize(NISTObjectIdentifiers.id_aes192_CBC, 192);
        verifyKeySize(NISTObjectIdentifiers.id_aes256_CBC, 256);

        verifyKeySize(NTTObjectIdentifiers.id_camellia128_cbc, 128);
        verifyKeySize(NTTObjectIdentifiers.id_camellia192_cbc, 192);
        verifyKeySize(NTTObjectIdentifiers.id_camellia256_cbc, 256);

        verifyKeySize(PKCSObjectIdentifiers.des_EDE3_CBC, 192);
    }

    private void verifyKeySize(ASN1ObjectIdentifier oid, int keySize)
        throws Exception
    {
        JceCRMFEncryptorBuilder encryptorBuilder = new JceCRMFEncryptorBuilder(oid).setProvider(BC);

        OutputEncryptor outputEncryptor = encryptorBuilder.build();

        assertEquals(keySize / 8, ((byte[])(outputEncryptor.getKey().getRepresentation())).length);
    }

    public void testEncryptedValue()
        throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();
        X509Certificate cert = makeV1Certificate(kp, "CN=Test", kp, "CN=Test");

        JcaEncryptedValueBuilder build = new JcaEncryptedValueBuilder(new JceAsymmetricKeyWrapper(cert.getPublicKey()).setProvider(BC), new JceCRMFEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BC).build());
        EncryptedValue value = build.build(cert);
        ValueDecryptorGenerator decGen = new JceAsymmetricValueDecryptorGenerator(kp.getPrivate()).setProvider(BC);

        // try direct
        encryptedValueParserTest(value, decGen, cert);

        // try indirect
        encryptedValueParserTest(EncryptedValue.getInstance(value.getEncoded()), decGen, cert);
    }

    public void testEncryptedValueOAEP1()
        throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(2048);

        KeyPair kp = kGen.generateKeyPair();
        X509Certificate cert = makeV1Certificate(kp, "CN=Test", kp, "CN=Test");

        AlgorithmIdentifier sha256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE);

        JcaEncryptedValueBuilder build = new JcaEncryptedValueBuilder(new JceAsymmetricKeyWrapper(
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP,
                new RSAESOAEPparams(sha256, new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, sha256),
                    RSAESOAEPparams.DEFAULT_P_SOURCE_ALGORITHM)),
            cert.getPublicKey()).setProvider(BC),
            new JceCRMFEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BC).build());

        EncryptedValue value = build.build(cert);
        ValueDecryptorGenerator decGen = new JceAsymmetricValueDecryptorGenerator(kp.getPrivate()).setProvider(BC);

        // try direct
        encryptedValueParserTest(value, decGen, cert);

        // try indirect
        encryptedValueParserTest(EncryptedValue.getInstance(value.getEncoded()), decGen, cert);
    }

    public void testEncryptedValueOAEP2()
        throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(2048);

        KeyPair kp = kGen.generateKeyPair();
        X509Certificate cert = makeV1Certificate(kp, "CN=Test", kp, "CN=Test");

        JcaEncryptedValueBuilder build = new JcaEncryptedValueBuilder(new JceAsymmetricKeyWrapper(
            new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), new PSource.PSpecified(new byte[2])),
            cert.getPublicKey()).setProvider(BC),
            new JceCRMFEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BC).build());

        EncryptedValue value = build.build(cert);

        assertEquals(PKCSObjectIdentifiers.id_RSAES_OAEP, value.getKeyAlg().getAlgorithm());
        assertEquals(NISTObjectIdentifiers.id_sha256, RSAESOAEPparams.getInstance(value.getKeyAlg().getParameters()).getHashAlgorithm().getAlgorithm());
        assertEquals(new DEROctetString(new byte[2]), RSAESOAEPparams.getInstance(value.getKeyAlg().getParameters()).getPSourceAlgorithm().getParameters());

        ValueDecryptorGenerator decGen = new JceAsymmetricValueDecryptorGenerator(kp.getPrivate()).setProvider(BC);

        // try direct
        encryptedValueParserTest(value, decGen, cert);

        // try indirect
        encryptedValueParserTest(EncryptedValue.getInstance(value.getEncoded()), decGen, cert);
    }

    private void encryptedValueParserTest(EncryptedValue value, ValueDecryptorGenerator decGen, X509Certificate cert)
        throws Exception
    {
        EncryptedValueParser  parser = new EncryptedValueParser(value);

        X509CertificateHolder holder = parser.readCertificateHolder(decGen);

        assertTrue(Arrays.areEqual(cert.getEncoded(), holder.getEncoded()));
    }

    public void testEncryptedValuePassphrase()
        throws Exception
    {
        char[] passphrase = PASSPHRASE.toCharArray();
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();
        X509Certificate cert = makeV1Certificate(kp, "CN=Test", kp, "CN=Test");

        EncryptedValueBuilder build = new EncryptedValueBuilder(new JceAsymmetricKeyWrapper(cert.getPublicKey()).setProvider(BC), new JceCRMFEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BC).build());
        EncryptedValue value = build.build(passphrase);
        ValueDecryptorGenerator decGen = new JceAsymmetricValueDecryptorGenerator(kp.getPrivate()).setProvider(BC);

        // try direct
        encryptedValuePassphraseParserTest(value, null, decGen, cert);

        // try indirect
        encryptedValuePassphraseParserTest(EncryptedValue.getInstance(value.getEncoded()), null, decGen, cert);
    }

    public void testEncryptedValuePassphraseWithPadding()
        throws Exception
    {
        char[] passphrase = PASSPHRASE.toCharArray();
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();
        X509Certificate cert = makeV1Certificate(kp, "CN=Test", kp, "CN=Test");

        BcFixedLengthMGF1Padder mgf1Padder = new BcFixedLengthMGF1Padder(200, new SecureRandom());
        EncryptedValueBuilder build = new EncryptedValueBuilder(new JceAsymmetricKeyWrapper(cert.getPublicKey()).setProvider(BC), new JceCRMFEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BC).build(), mgf1Padder);
        EncryptedValue value = build.build(passphrase);
        ValueDecryptorGenerator decGen = new JceAsymmetricValueDecryptorGenerator(kp.getPrivate()).setProvider(BC);

        // try direct
        encryptedValuePassphraseParserTest(value, mgf1Padder, decGen, cert);

        // try indirect
        encryptedValuePassphraseParserTest(EncryptedValue.getInstance(value.getEncoded()), mgf1Padder, decGen, cert);
    }

    private void encryptedValuePassphraseParserTest(EncryptedValue value, EncryptedValuePadder padder, ValueDecryptorGenerator decGen, X509Certificate cert)
        throws Exception
    {
        EncryptedValueParser  parser = new EncryptedValueParser(value, padder);

        assertTrue(Arrays.areEqual(PASSPHRASE.toCharArray(), parser.readPassphrase(decGen)));
    }

    private static X509Certificate makeV1Certificate(KeyPair subKP, String _subDN, KeyPair issKP, String _issDN)
        throws GeneralSecurityException, IOException, OperatorCreationException
    {

        PublicKey subPub  = subKP.getPublic();
        PrivateKey issPriv = issKP.getPrivate();
        PublicKey  issPub  = issKP.getPublic();

        X509v1CertificateBuilder v1CertGen = new JcaX509v1CertificateBuilder(
            new X500Name(_issDN),
            BigInteger.valueOf(System.currentTimeMillis()),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
            new X500Name(_subDN),
            subPub);

        JcaContentSignerBuilder signerBuilder = null;

        if (issPub instanceof RSAPublicKey)
        {
            signerBuilder = new JcaContentSignerBuilder("SHA1WithRSA");
        }
        else if (issPub.getAlgorithm().equals("DSA"))
        {
            signerBuilder = new JcaContentSignerBuilder("SHA1withDSA");
        }
        else if (issPub.getAlgorithm().equals("EC"))
        {
            signerBuilder = new JcaContentSignerBuilder("SHA256withECDSA");
        }
        else if (issPub.getAlgorithm().equals("ECDSA"))
        {
            signerBuilder = new JcaContentSignerBuilder("SHA1withECDSA");
        }
        else if (issPub.getAlgorithm().equals("ECGOST3410"))
        {
            signerBuilder = new JcaContentSignerBuilder("GOST3411withECGOST3410");
        }
        else
        {
            signerBuilder = new JcaContentSignerBuilder("GOST3411WithGOST3410");
        }

        signerBuilder.setProvider(BC);

        X509Certificate _cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(v1CertGen.build(signerBuilder.build(issPriv)));

        _cert.checkValidity(new Date());
        _cert.verify(issPub);

        return _cert;
    }
}