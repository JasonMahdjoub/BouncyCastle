package com.distrimind.bouncycastle.cert.cmp.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.DSAParameterSpec;
import java.util.Date;

import junit.framework.TestCase;
import com.distrimind.bouncycastle.asn1.cmp.CMPCertificate;
import com.distrimind.bouncycastle.asn1.cmp.PKIBody;
import com.distrimind.bouncycastle.asn1.cmp.PKIStatus;
import com.distrimind.bouncycastle.asn1.cmp.PKIStatusInfo;
import com.distrimind.bouncycastle.asn1.crmf.CertTemplate;
import com.distrimind.bouncycastle.asn1.crmf.SubsequentMessage;
import com.distrimind.bouncycastle.asn1.x500.X500Name;
import com.distrimind.bouncycastle.asn1.x509.BasicConstraints;
import com.distrimind.bouncycastle.asn1.x509.Extension;
import com.distrimind.bouncycastle.asn1.x509.GeneralName;
import com.distrimind.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import com.distrimind.bouncycastle.cert.CertException;
import com.distrimind.bouncycastle.cert.CertIOException;
import com.distrimind.bouncycastle.cert.X509CertificateHolder;
import com.distrimind.bouncycastle.cert.X509v3CertificateBuilder;
import com.distrimind.bouncycastle.cert.cmp.CertificateConfirmationContent;
import com.distrimind.bouncycastle.cert.cmp.CertificateConfirmationContentBuilder;
import com.distrimind.bouncycastle.cert.cmp.ProtectedPKIMessage;
import com.distrimind.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import com.distrimind.bouncycastle.cert.crmf.CertificateRepMessage;
import com.distrimind.bouncycastle.cert.crmf.CertificateRepMessageBuilder;
import com.distrimind.bouncycastle.cert.crmf.CertificateReqMessages;
import com.distrimind.bouncycastle.cert.crmf.CertificateReqMessagesBuilder;
import com.distrimind.bouncycastle.cert.crmf.CertificateRequestMessage;
import com.distrimind.bouncycastle.cert.crmf.CertificateResponse;
import com.distrimind.bouncycastle.cert.crmf.CertificateResponseBuilder;
import com.distrimind.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessageBuilder;
import com.distrimind.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import com.distrimind.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import com.distrimind.bouncycastle.cms.CMSAlgorithm;
import com.distrimind.bouncycastle.cms.CMSEnvelopedData;
import com.distrimind.bouncycastle.cms.CMSEnvelopedDataGenerator;
import com.distrimind.bouncycastle.cms.CMSProcessableByteArray;
import com.distrimind.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import com.distrimind.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import com.distrimind.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import com.distrimind.bouncycastle.crypto.CryptoServicesRegistrar;
import com.distrimind.bouncycastle.crypto.params.DHParameters;
import com.distrimind.bouncycastle.crypto.params.DSAParameters;
import com.distrimind.bouncycastle.jcajce.spec.DHDomainParameterSpec;
import com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider;
import com.distrimind.bouncycastle.operator.ContentSigner;
import com.distrimind.bouncycastle.operator.ContentVerifierProvider;
import com.distrimind.bouncycastle.operator.MacCalculator;
import com.distrimind.bouncycastle.operator.OperatorCreationException;
import com.distrimind.bouncycastle.operator.PBEMacCalculatorProvider;
import com.distrimind.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import com.distrimind.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import com.distrimind.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import com.distrimind.bouncycastle.operator.jcajce.JceAsymmetricKeyWrapper;
import com.distrimind.bouncycastle.pkcs.jcajce.JcePBMac1CalculatorBuilder;
import com.distrimind.bouncycastle.pkcs.jcajce.JcePBMac1CalculatorProviderBuilder;
import com.distrimind.bouncycastle.util.BigIntegers;

public class ElgamalDSATest
    extends TestCase
{
    public void setUp()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void tearDown()
    {

    }

    public void testElgamalWithDSA()
        throws Exception
    {
        char[] senderMacPassword = "secret".toCharArray();
        GeneralName sender = new GeneralName(new X500Name("CN=Elgamal Subject"));
        GeneralName recipient = new GeneralName(new X500Name("CN=DSA Issuer"));

        KeyPairGenerator dsaKpGen = KeyPairGenerator.getInstance("DSA", "BC");

        DSAParameters dsaParams = (DSAParameters)CryptoServicesRegistrar.getSizedProperty(CryptoServicesRegistrar.Property.DSA_DEFAULT_PARAMS, 2048);
        
        dsaKpGen.initialize(new DSAParameterSpec(dsaParams.getP(), dsaParams.getQ(), dsaParams.getG()));

        KeyPair dsaKp = dsaKpGen.generateKeyPair();

        X509CertificateHolder caCert = makeV3Certificate("CN=DSA Issuer", dsaKp);

        KeyPairGenerator elgKpGen = KeyPairGenerator.getInstance("Elgamal", "BC");

        elgKpGen.initialize(
            new DHDomainParameterSpec((DHParameters)CryptoServicesRegistrar.getSizedProperty(CryptoServicesRegistrar.Property.DH_DEFAULT_PARAMS, 2048)));
            
        KeyPair elgKp = elgKpGen.generateKeyPair();

        // initial request

        JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigIntegers.ONE);

        certReqBuild
            .setPublicKey(elgKp.getPublic())
            .setSubject(X500Name.getInstance(sender.getName()))
            .setProofOfPossessionSubsequentMessage(SubsequentMessage.encrCert);

        CertificateReqMessagesBuilder certReqMsgsBldr = new CertificateReqMessagesBuilder();

        certReqMsgsBldr.addRequest(certReqBuild.build());

        MacCalculator senderMacCalculator = new JcePBMac1CalculatorBuilder("HmacSHA256", 256).setProvider("BC").build(senderMacPassword);

        ProtectedPKIMessage message = new ProtectedPKIMessageBuilder(sender, recipient)
            .setBody(PKIBody.TYPE_INIT_REQ, certReqMsgsBldr.build())
            .build(senderMacCalculator);

        // extract

        assertTrue(message.getProtectionAlgorithm().equals(senderMacCalculator.getAlgorithmIdentifier()));

        PBEMacCalculatorProvider macCalcProvider = new JcePBMac1CalculatorProviderBuilder().setProvider("BC").build();

        assertTrue(message.verify(macCalcProvider, senderMacPassword));

        assertEquals(PKIBody.TYPE_INIT_REQ, message.getBody().getType());

        CertificateReqMessages requestMessages = CertificateReqMessages.fromPKIBody(message.getBody());
        CertificateRequestMessage senderReqMessage = requestMessages.getRequests()[0];
        CertTemplate certTemplate = senderReqMessage.getCertTemplate();

        X509CertificateHolder cert = makeV3Certificate(certTemplate.getPublicKey(), certTemplate.getSubject(), dsaKp, "CN=DSA Issuer");

        // Send response with encrypted certificate
        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        // note: use cert req ID as key ID, don't want to use issuer/serial in this case!

        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(senderReqMessage.getCertReqId().getEncoded(),
                    new JceAsymmetricKeyWrapper(new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert))));

        CMSEnvelopedData encryptedCert = edGen.generate(
                                new CMSProcessableByteArray(new CMPCertificate(cert.toASN1Structure()).getEncoded()),
                                new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider("BC").build());

        CertificateResponseBuilder certRespBuilder = new CertificateResponseBuilder(senderReqMessage.getCertReqId(), new PKIStatusInfo(PKIStatus.granted));

        certRespBuilder.withCertificate(encryptedCert);

        CertificateRepMessageBuilder repMessageBuilder = new CertificateRepMessageBuilder(caCert);

        repMessageBuilder.addCertificateResponse(certRespBuilder.build());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withDSA").setProvider("BC").build(dsaKp.getPrivate());

        CertificateRepMessage repMessage = repMessageBuilder.build();

        ProtectedPKIMessage responsePkixMessage = new ProtectedPKIMessageBuilder(sender, recipient)
            .setBody(PKIBody.TYPE_INIT_REP, repMessage)
            .build(signer);

        // decrypt the certificate

        assertTrue(responsePkixMessage.verify(new JcaContentVerifierProviderBuilder().build(caCert)));

        CertificateRepMessage certRepMessage = CertificateRepMessage.fromPKIBody(responsePkixMessage.getBody());

        CertificateResponse certResp = certRepMessage.getResponses()[0];

        X509CertificateHolder receivedCert = new X509CertificateHolder(certResp.getCertificate(new JceKeyTransEnvelopedRecipient(elgKp.getPrivate())).getX509v3PKCert());

        X509CertificateHolder caCertHolder = certRepMessage.getX509Certificates()[0];

        assertEquals(true, receivedCert.isSignatureValid(new JcaContentVerifierProviderBuilder().build(caCertHolder)));

        // confirmation message calculation

        CertificateConfirmationContent content = new CertificateConfirmationContentBuilder()
            .addAcceptedCertificate(cert, BigInteger.ONE)
            .build(new JcaDigestCalculatorProviderBuilder().build());

        message = new ProtectedPKIMessageBuilder(sender, recipient)
            .setBody(PKIBody.TYPE_CERT_CONFIRM, content)
            .build(senderMacCalculator);

        assertTrue(content.getStatusMessages()[0].isVerified(receivedCert, new JcaDigestCalculatorProviderBuilder().build()));
        assertEquals(PKIBody.TYPE_CERT_CONFIRM, message.getBody().getType());

        // confirmation receiving

        CertificateConfirmationContent recContent = CertificateConfirmationContent.fromPKIBody(message.getBody());

        assertTrue(recContent.getStatusMessages()[0].isVerified(receivedCert, new JcaDigestCalculatorProviderBuilder().build()));
    }

    private static X509CertificateHolder makeV3Certificate(String _subDN, KeyPair issKP)
        throws OperatorCreationException, CertException, CertIOException
    {
        PrivateKey issPriv = issKP.getPrivate();
        PublicKey  issPub  = issKP.getPublic();

        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
            new X500Name(_subDN),
            BigInteger.valueOf(System.currentTimeMillis()),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
            new X500Name(_subDN),
            issKP.getPublic());

        certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withDSA").build(issPriv);

        X509CertificateHolder certHolder = certGen.build(signer);

        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder().build(issPub);

        assertTrue(certHolder.isSignatureValid(verifier));

        return certHolder;
    }

    private static X509CertificateHolder makeV3Certificate(SubjectPublicKeyInfo pubKey, X500Name _subDN, KeyPair issKP, String _issDN)
        throws OperatorCreationException, CertException, CertIOException
    {
        PrivateKey issPriv = issKP.getPrivate();
        PublicKey  issPub  = issKP.getPublic();

        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
            new X500Name(_issDN),
            BigInteger.valueOf(System.currentTimeMillis()),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
            _subDN,
            pubKey);

        certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withDSA").build(issPriv);

        X509CertificateHolder certHolder = certGen.build(signer);

        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder().build(issPub);

        assertTrue(certHolder.isSignatureValid(verifier));

        return certHolder;
    }
}
