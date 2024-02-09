package com.distrimind.bouncycastle.cert.cmp.test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import com.distrimind.bouncycastle.test.TestResourceFinder;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import com.distrimind.bouncycastle.asn1.ASN1Integer;
import com.distrimind.bouncycastle.asn1.ASN1Primitive;
import com.distrimind.bouncycastle.asn1.DERSequence;
import com.distrimind.bouncycastle.asn1.cmp.CMPCertificate;
import com.distrimind.bouncycastle.asn1.cmp.CertConfirmContent;
import com.distrimind.bouncycastle.asn1.cmp.CertOrEncCert;
import com.distrimind.bouncycastle.asn1.cmp.CertRepMessage;
import com.distrimind.bouncycastle.asn1.cmp.CertResponse;
import com.distrimind.bouncycastle.asn1.cmp.CertifiedKeyPair;
import com.distrimind.bouncycastle.asn1.cmp.PKIBody;
import com.distrimind.bouncycastle.asn1.cmp.PKIMessage;
import com.distrimind.bouncycastle.asn1.cmp.PKIStatus;
import com.distrimind.bouncycastle.asn1.cmp.PKIStatusInfo;
import com.distrimind.bouncycastle.asn1.crmf.CertReqMessages;
import com.distrimind.bouncycastle.asn1.crmf.CertReqMsg;
import com.distrimind.bouncycastle.asn1.crmf.EncryptedKey;
import com.distrimind.bouncycastle.asn1.crmf.EncryptedValue;
import com.distrimind.bouncycastle.asn1.crmf.ProofOfPossession;
import com.distrimind.bouncycastle.asn1.crmf.SubsequentMessage;
import com.distrimind.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import com.distrimind.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import com.distrimind.bouncycastle.asn1.x500.X500Name;
import com.distrimind.bouncycastle.asn1.x509.GeneralName;
import com.distrimind.bouncycastle.cert.CertException;
import com.distrimind.bouncycastle.cert.X509CertificateHolder;
import com.distrimind.bouncycastle.cert.X509v3CertificateBuilder;
import com.distrimind.bouncycastle.cert.cmp.CertificateConfirmationContent;
import com.distrimind.bouncycastle.cert.cmp.CertificateConfirmationContentBuilder;
import com.distrimind.bouncycastle.cert.cmp.CertificateStatus;
import com.distrimind.bouncycastle.cert.cmp.GeneralPKIMessage;
import com.distrimind.bouncycastle.cert.cmp.ProtectedPKIMessage;
import com.distrimind.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import com.distrimind.bouncycastle.cert.crmf.CertificateRequestMessage;
import com.distrimind.bouncycastle.cert.crmf.CertificateRequestMessageBuilder;
import com.distrimind.bouncycastle.cert.crmf.PKMACBuilder;
import com.distrimind.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessageBuilder;
import com.distrimind.bouncycastle.cert.crmf.jcajce.JcaEncryptedValueBuilder;
import com.distrimind.bouncycastle.cert.crmf.jcajce.JceCRMFEncryptorBuilder;
import com.distrimind.bouncycastle.cert.crmf.jcajce.JcePKMACValuesCalculator;
import com.distrimind.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import com.distrimind.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import com.distrimind.bouncycastle.cms.CMSAlgorithm;
import com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider;
import com.distrimind.bouncycastle.operator.AsymmetricKeyUnwrapper;
import com.distrimind.bouncycastle.operator.ContentSigner;
import com.distrimind.bouncycastle.operator.ContentVerifierProvider;
import com.distrimind.bouncycastle.operator.MacCalculator;
import com.distrimind.bouncycastle.operator.OperatorCreationException;
import com.distrimind.bouncycastle.operator.PBEMacCalculatorProvider;
import com.distrimind.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import com.distrimind.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import com.distrimind.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import com.distrimind.bouncycastle.operator.jcajce.JceAsymmetricKeyUnwrapper;
import com.distrimind.bouncycastle.operator.jcajce.JceAsymmetricKeyWrapper;
import com.distrimind.bouncycastle.operator.jcajce.JceInputDecryptorProviderBuilder;
import com.distrimind.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import com.distrimind.bouncycastle.pkcs.jcajce.JcePBMac1CalculatorBuilder;
import com.distrimind.bouncycastle.pkcs.jcajce.JcePBMac1CalculatorProviderBuilder;
import com.distrimind.bouncycastle.util.Arrays;
import com.distrimind.bouncycastle.util.io.Streams;

public class AllTests
    extends TestCase
{
    private static final byte[] TEST_DATA = "Hello world!".getBytes();
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

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

    public void testProtectedMessage()
        throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();
        X509CertificateHolder cert = makeV3Certificate(kp, "CN=Test", kp, "CN=Test");

        GeneralName sender = new GeneralName(new X500Name("CN=Sender"));
        GeneralName recipient = new GeneralName(new X500Name("CN=Recip"));

        ContentSigner signer = new JcaContentSignerBuilder("MD5WithRSAEncryption").setProvider(BC).build(kp.getPrivate());
        ProtectedPKIMessage message = new ProtectedPKIMessageBuilder(sender, recipient)
                                                  .setBody(new PKIBody(PKIBody.TYPE_INIT_REP, CertRepMessage.getInstance(new DERSequence(new DERSequence()))))
                                                  .addCMPCertificate(cert)
                                                  .build(signer);

        X509Certificate jcaCert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(message.getCertificates()[0]);
        ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder().setProvider(BC).build(jcaCert.getPublicKey());

        assertTrue(message.verify(verifierProvider));

        assertEquals(sender, message.getHeader().getSender());
        assertEquals(recipient, message.getHeader().getRecipient());
    }

    public void testMacProtectedMessage()
        throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();
        X509CertificateHolder cert = makeV3Certificate(kp, "CN=Test", kp, "CN=Test");

        GeneralName sender = new GeneralName(new X500Name("CN=Sender"));
        GeneralName recipient = new GeneralName(new X500Name("CN=Recip"));

        ProtectedPKIMessage message = new ProtectedPKIMessageBuilder(sender, recipient)
                                                  .setBody(new PKIBody(PKIBody.TYPE_INIT_REP, CertRepMessage.getInstance(new DERSequence(new DERSequence()))))
                                                  .addCMPCertificate(cert)
                                                  .build(new PKMACBuilder(new JcePKMACValuesCalculator().setProvider(BC)).build("secret".toCharArray()));

        PKMACBuilder pkMacBuilder = new PKMACBuilder(new JcePKMACValuesCalculator().setProvider(BC));

        assertTrue(message.verify(pkMacBuilder, "secret".toCharArray()));

        assertEquals(sender, message.getHeader().getSender());
        assertEquals(recipient, message.getHeader().getRecipient());
    }

    public void testPBMac1ProtectedMessage()
        throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();
        X509CertificateHolder cert = makeV3Certificate(kp, "CN=Test", kp, "CN=Test");

        GeneralName sender = new GeneralName(new X500Name("CN=Sender"));
        GeneralName recipient = new GeneralName(new X500Name("CN=Recip"));

        MacCalculator pbCalculator = new JcePBMac1CalculatorBuilder("HmacSHA256", 256).setProvider("BC").build("secret".toCharArray());

        ProtectedPKIMessage message = new ProtectedPKIMessageBuilder(sender, recipient)
                                                  .setBody(new PKIBody(PKIBody.TYPE_INIT_REP, CertRepMessage.getInstance(new DERSequence(new DERSequence()))))
                                                  .addCMPCertificate(cert)
                                                  .build(pbCalculator);

        PBEMacCalculatorProvider macProvider = new JcePBMac1CalculatorProviderBuilder().setProvider("BC").build();

        assertTrue(message.verify(macProvider, "secret".toCharArray()));

        assertEquals(sender, message.getHeader().getSender());
        assertEquals(recipient, message.getHeader().getRecipient());
    }
    
    public void testConfirmationMessage()
        throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();
        X509CertificateHolder cert = makeV3Certificate(kp, "CN=Test", kp, "CN=Test");

        GeneralName sender = new GeneralName(new X500Name("CN=Sender"));
        GeneralName recipient = new GeneralName(new X500Name("CN=Recip"));

        CertificateConfirmationContent content = new CertificateConfirmationContentBuilder()
                             .addAcceptedCertificate(cert, BigInteger.valueOf(1))
                             .build(new JcaDigestCalculatorProviderBuilder().build());

        ContentSigner signer = new JcaContentSignerBuilder("MD5WithRSAEncryption").setProvider(BC).build(kp.getPrivate());
        ProtectedPKIMessage message = new ProtectedPKIMessageBuilder(sender, recipient)
                                                  .setBody(new PKIBody(PKIBody.TYPE_CERT_CONFIRM, content.toASN1Structure()))
                                                  .addCMPCertificate(cert)
                                                  .build(signer);

        X509Certificate jcaCert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(message.getCertificates()[0]);
        ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder().setProvider(BC).build(jcaCert.getPublicKey());

        assertTrue(message.verify(verifierProvider));

        assertEquals(sender, message.getHeader().getSender());
        assertEquals(recipient, message.getHeader().getRecipient());

        content = new CertificateConfirmationContent(CertConfirmContent.getInstance(message.getBody().getContent()));

        CertificateStatus[] statusList = content.getStatusMessages();

        assertEquals(1, statusList.length);
        assertTrue(statusList[0].isVerified(cert, new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()));
    }

    public void testSampleCr()
        throws Exception
    {
        PKIMessage msg = loadMessage("sample_cr.der");
        ProtectedPKIMessage procMsg = new ProtectedPKIMessage(new GeneralPKIMessage(msg));

        assertTrue(procMsg.verify(new PKMACBuilder(new JcePKMACValuesCalculator().setProvider(BC)), "TopSecret1234".toCharArray()));
    }

    public void testSubsequentMessage()
        throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();
        X509CertificateHolder cert = makeV3Certificate(kp, "CN=Test", kp, "CN=Test");

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(
                    kp.getPrivate());

        GeneralName user = new GeneralName(new X500Name("CN=Test"));

        CertificateRequestMessageBuilder builder = new JcaCertificateRequestMessageBuilder(
                    BigInteger.valueOf(1)).setPublicKey(kp.getPublic()).setProofOfPossessionSubsequentMessage(
                    SubsequentMessage.encrCert);

                ProtectedPKIMessage certRequestMsg = new ProtectedPKIMessageBuilder(user,
                    user).setTransactionID(new byte[] { 1, 2, 3, 4, 5 }).setBody(
                    new PKIBody(PKIBody.TYPE_KEY_UPDATE_REQ, new CertReqMessages(builder.build().toASN1Structure()))).addCMPCertificate(
                    cert).build(signer);

        ProtectedPKIMessage msg = new ProtectedPKIMessage(new GeneralPKIMessage(certRequestMsg.toASN1Structure().getEncoded()));

        CertReqMessages reqMsgs = CertReqMessages.getInstance(msg.getBody().getContent());

        CertReqMsg reqMsg = reqMsgs.toCertReqMsgArray()[0];

        assertEquals(ProofOfPossession.TYPE_KEY_ENCIPHERMENT, reqMsg.getPop().getType());
    }

    public void testServerSideKey()
        throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();
        X509CertificateHolder cert = makeV3Certificate(kp, "CN=Test", kp, "CN=Test");

        JcaEncryptedValueBuilder encBldr = new JcaEncryptedValueBuilder(
            new JceAsymmetricKeyWrapper(kp.getPublic()).setProvider(BC),
            new JceCRMFEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BC).build());

        GeneralName sender = new GeneralName(new X500Name("CN=Sender"));
        GeneralName recipient = new GeneralName(new X500Name("CN=Recip"));

        CertRepMessage msg = new CertRepMessage(null, new CertResponse[] {
            new CertResponse(
                new ASN1Integer(2),
                new PKIStatusInfo(PKIStatus.granted),
                new CertifiedKeyPair(
                    new CertOrEncCert(CMPCertificate.getInstance(cert.getEncoded())),
                    encBldr.build(kp.getPrivate()),
                    null), null) });

        ContentSigner signer = new JcaContentSignerBuilder("MD5WithRSAEncryption").setProvider(BC).build(kp.getPrivate());
        ProtectedPKIMessage message = new ProtectedPKIMessageBuilder(sender, recipient)
                                                  .setBody(new PKIBody(PKIBody.TYPE_INIT_REP, msg))
                                                  .addCMPCertificate(cert)
                                                  .build(signer);

        X509Certificate jcaCert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(message.getCertificates()[0]);
        ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder().setProvider(BC).build(jcaCert.getPublicKey());

        assertTrue(message.verify(verifierProvider));

        assertEquals(sender, message.getHeader().getSender());
        assertEquals(recipient, message.getHeader().getRecipient());

        CertRepMessage content = CertRepMessage.getInstance(message.getBody().getContent());

        CertResponse[] responseList = content.getResponse();

        assertEquals(1, responseList.length);

        CertResponse response = responseList[0];

        assertEquals(PKIStatus.granted.getValue(), response.getStatus().getStatus());

        CertifiedKeyPair certKp = response.getCertifiedKeyPair();

        // steps to unwrap private key
        EncryptedKey encKey = certKp.getPrivateKey();
        EncryptedValue encValue = EncryptedValue.getInstance(encKey.getValue());
        // recover symmetric key
        AsymmetricKeyUnwrapper unwrapper = new JceAsymmetricKeyUnwrapper(encValue.getKeyAlg(), kp.getPrivate());
        
        byte[] secKeyBytes = (byte[])unwrapper.generateUnwrappedKey(encValue.getKeyAlg(), encValue.getEncSymmKey().getBytes()).getRepresentation();

        // recover private key
        PKCS8EncryptedPrivateKeyInfo respInfo = new PKCS8EncryptedPrivateKeyInfo(
            new EncryptedPrivateKeyInfo(encValue.getSymmAlg(), encValue.getEncValue().getBytes()));

        PrivateKeyInfo keyInfo = respInfo.decryptPrivateKeyInfo(new JceInputDecryptorProviderBuilder().setProvider("BC").build(secKeyBytes));

        assertEquals(keyInfo.getPrivateKeyAlgorithm(), encValue.getIntendedAlg());
        assertTrue(Arrays.areEqual(kp.getPrivate().getEncoded(), keyInfo.getEncoded()));
    }


    public void testNotBeforeNotAfter()
        throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();

        doNotBeforeNotAfterTest(kp, new Date(0L), new Date(60000L));
        doNotBeforeNotAfterTest(kp, null, new Date(60000L));
        doNotBeforeNotAfterTest(kp, new Date(0L), null);
    }

    private void doNotBeforeNotAfterTest(KeyPair kp, Date notBefore, Date notAfter)
        throws Exception
    {
        CertificateRequestMessageBuilder builder = new JcaCertificateRequestMessageBuilder(
                    BigInteger.valueOf(1)).setPublicKey(kp.getPublic()).setProofOfPossessionSubsequentMessage(
                    SubsequentMessage.encrCert);

        builder.setValidity(notBefore, notAfter);

        CertificateRequestMessage message = builder.build();

        if (notBefore != null)
        {
            assertEquals(notBefore.getTime(), message.getCertTemplate().getValidity().getNotBefore().getDate().getTime());
        }
        else
        {
            assertNull(message.getCertTemplate().getValidity().getNotBefore());
        }

        if (notAfter != null)
        {
            assertEquals(notAfter.getTime(), message.getCertTemplate().getValidity().getNotAfter().getDate().getTime());
        }
        else
        {
            assertNull(message.getCertTemplate().getValidity().getNotAfter());
        }
    }

    private static X509CertificateHolder makeV3Certificate(KeyPair subKP, String _subDN, KeyPair issKP, String _issDN)
        throws GeneralSecurityException, IOException, OperatorCreationException, CertException
    {

        PublicKey subPub  = subKP.getPublic();
        PrivateKey issPriv = issKP.getPrivate();
        PublicKey  issPub  = issKP.getPublic();

        X509v3CertificateBuilder v1CertGen = new JcaX509v3CertificateBuilder(
            new X500Name(_issDN),
            BigInteger.valueOf(System.currentTimeMillis()),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
            new X500Name(_subDN),
            subPub);

        ContentSigner signer = new JcaContentSignerBuilder("SHA1WithRSA").setProvider(BC).build(issPriv);

        X509CertificateHolder certHolder = v1CertGen.build(signer);

        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder().setProvider(BC).build(issPub);

        assertTrue(certHolder.isSignatureValid(verifier));

        return certHolder;
    }

    private static PKIMessage loadMessage(String name)
    {
        try
        {
            return PKIMessage.getInstance(ASN1Primitive.fromByteArray(Streams.readAll(TestResourceFinder.findTestResource("/cmp", name))));
        }
        catch (IOException e)
        {
            throw new RuntimeException(e.toString());
        }
    }
}