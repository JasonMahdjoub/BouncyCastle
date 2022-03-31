package com.distrimind.bouncycastle.cert.test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import com.distrimind.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import com.distrimind.bouncycastle.asn1.x500.X500Name;
import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.asn1.x509.BasicConstraints;
import com.distrimind.bouncycastle.asn1.x509.ExtendedKeyUsage;
import com.distrimind.bouncycastle.asn1.x509.Extension;
import com.distrimind.bouncycastle.asn1.x509.KeyPurposeId;
import com.distrimind.bouncycastle.asn1.x509.KeyUsage;
import com.distrimind.bouncycastle.cert.X509CertificateHolder;
import com.distrimind.bouncycastle.cert.X509v3CertificateBuilder;
import com.distrimind.bouncycastle.cms.CMSException;
import com.distrimind.bouncycastle.cms.CMSProcessableByteArray;
import com.distrimind.bouncycastle.cms.CMSSignedData;
import com.distrimind.bouncycastle.cms.CMSSignedDataGenerator;
import com.distrimind.bouncycastle.cms.CMSTypedData;
import com.distrimind.bouncycastle.cms.SignerId;
import com.distrimind.bouncycastle.cms.SignerInfoGenerator;
import com.distrimind.bouncycastle.cms.SignerInformation;
import com.distrimind.bouncycastle.cms.SignerInformationStore;
import com.distrimind.bouncycastle.cms.SignerInformationVerifier;
import com.distrimind.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import com.distrimind.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;
import com.distrimind.bouncycastle.crypto.params.ECDomainParameters;
import com.distrimind.bouncycastle.crypto.params.ECPrivateKeyParameters;
import com.distrimind.bouncycastle.crypto.params.ECPublicKeyParameters;
import com.distrimind.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import com.distrimind.bouncycastle.jce.interfaces.ECPrivateKey;
import com.distrimind.bouncycastle.jce.interfaces.ECPublicKey;
import com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider;
import com.distrimind.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import com.distrimind.bouncycastle.jce.spec.ECParameterSpec;
import com.distrimind.bouncycastle.operator.ContentSigner;
import com.distrimind.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import com.distrimind.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import com.distrimind.bouncycastle.operator.OperatorCreationException;
import com.distrimind.bouncycastle.operator.bc.BcContentSignerBuilder;
import com.distrimind.bouncycastle.operator.bc.BcECContentSignerBuilder;
import com.distrimind.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import com.distrimind.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import com.distrimind.bouncycastle.util.Store;
import com.distrimind.bouncycastle.util.test.SimpleTest;
import com.distrimind.bouncycastle.util.test.Test;
import com.distrimind.bouncycastle.util.test.TestResult;


public class GOST3410_2012CMSTest
    extends SimpleTest
{

    public String getName()
    {
        return "GOST3410 2012 CMS TEST";
    }

    public void performTest()
        throws Exception
    {
        if (Security.getProvider("BC").containsKey("KeyFactory.ECGOST3410-2012"))
        {
            cmsTest("GOST-3410-2012", "Tc26-Gost-3410-12-512-paramSetA", "GOST3411-2012-512WITHECGOST3410-2012-512",
                RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512.getId());
            cmsTest("GOST-3410-2012", "Tc26-Gost-3410-12-512-paramSetB", "GOST3411-2012-512WITHECGOST3410-2012-512",
                RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512.getId());
            cmsTest("GOST-3410-2012", "Tc26-Gost-3410-12-512-paramSetC", "GOST3411-2012-512WITHECGOST3410-2012-512",
                RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512.getId());
            cmsTest("GOST-3410-2012", "Tc26-Gost-3410-12-256-paramSetA", "GOST3411-2012-256WITHECGOST3410-2012-256",
                RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256.getId());
        }
    }

    public void cmsTest(String keyAlgorithm, String paramName, String signAlgorithm, String digestId)
    {
        try
        {
            KeyPairGenerator keyPairGenerator =
                KeyPairGenerator.getInstance(keyAlgorithm, "BC");
            keyPairGenerator.initialize(new ECNamedCurveGenParameterSpec(paramName), new SecureRandom());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            X509CertificateHolder signingCertificate = selfSignedCertificate(keyPair, signAlgorithm);

            // CMS
            byte[] dataContent = new byte[]{1, 2, 3, 4, 33, 22, 11, 33, 52, 21, 23};
            CMSTypedData cmsTypedData = new CMSProcessableByteArray(dataContent);


            final JcaSignerInfoGeneratorBuilder signerInfoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider("BC").build());

            final ContentSigner contentSigner = new
                JcaContentSignerBuilder(signAlgorithm).setProvider("BC")
                .build(keyPair.getPrivate());

            final SignerInfoGenerator signerInfoGenerator = signerInfoGeneratorBuilder.build(contentSigner, signingCertificate);

            CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator();

            cmsSignedDataGenerator.addCertificate(signingCertificate);
            cmsSignedDataGenerator.addSignerInfoGenerator(signerInfoGenerator);

            CMSSignedData cmsSignedData = cmsSignedDataGenerator.generate(cmsTypedData, false);
            if (cmsSignedData == null)
            {
                fail("Cant create CMS");
            }

            boolean algIdContains = false;
            for (Iterator it = cmsSignedData.getDigestAlgorithmIDs().iterator(); it.hasNext();)
            {
                AlgorithmIdentifier algorithmIdentifier = (AlgorithmIdentifier)it.next();
                if (algorithmIdentifier.getAlgorithm().getId().equals(digestId))
                {
                    algIdContains = true;
                    break;
                }
            }
            if (!algIdContains)
            {
                fail("identifier not valid");
            }
            boolean result = verify(cmsSignedData, cmsTypedData);
            if (!result)
            {
                fail("Verification fails ");
            }

        }
        catch (Exception ex)
        {
            ex.printStackTrace();
            fail("fail with exception:", ex);
        }
    }

    private boolean verify(CMSSignedData signature, CMSTypedData typedData)
        throws CertificateException, OperatorCreationException, IOException, CMSException
    {
        CMSSignedData signedDataToVerify = new CMSSignedData(typedData, signature.getEncoded());
        Store certs = signedDataToVerify.getCertificates();
        SignerInformationStore signers = signedDataToVerify.getSignerInfos();
        Collection<SignerInformation> c = signers.getSigners();
        for (Iterator it = c.iterator(); it.hasNext();)
        {
            SignerInformation signer = (SignerInformation)it.next();
            SignerId signerId = signer.getSID();
            Collection certCollection = certs.getMatches(signerId);

            Iterator certIt = certCollection.iterator();
            Object certificate = certIt.next();
            SignerInformationVerifier verifier =
                new JcaSimpleSignerInfoVerifierBuilder()
                    .setProvider("BC").build((X509CertificateHolder)certificate);


            boolean result = signer.verify(verifier);
            if (result)
            {
                return true;
            }
        }
        return false;
    }

    private X509CertificateHolder selfSignedCertificate(KeyPair keyPair, String signatureAlgName)
        throws IOException, OperatorCreationException
    {

        X500Name name = new X500Name("CN=BB, C=aa");
        ECPublicKey k = (ECPublicKey)keyPair.getPublic();
        ECParameterSpec s = k.getParameters();
        ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(
            k.getQ(),
            new ECDomainParameters(s.getCurve(), s.getG(), s.getN()));

        ECPrivateKey kk = (ECPrivateKey)keyPair.getPrivate();
        ECParameterSpec ss = kk.getParameters();

        ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(
            kk.getD(),
            new ECDomainParameters(ss.getCurve(), ss.getG(), ss.getN()));

        AsymmetricKeyParameter publicKey = ecPublicKeyParameters;
        AsymmetricKeyParameter privateKey = ecPrivateKeyParameters;
        X509v3CertificateBuilder myCertificateGenerator = new X509v3CertificateBuilder(
            name,
            BigInteger.ONE,
            new Date(),
            new Date(new Date().getTime() + 364 * 50 * 3600),
            name,
            SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey));

        DefaultSignatureAlgorithmIdentifierFinder signatureAlgorithmIdentifierFinder = new DefaultSignatureAlgorithmIdentifierFinder();
        DefaultDigestAlgorithmIdentifierFinder digestAlgorithmIdentifierFinder = new DefaultDigestAlgorithmIdentifierFinder();

        AlgorithmIdentifier signAlgId = signatureAlgorithmIdentifierFinder.find(signatureAlgName);
        AlgorithmIdentifier digestAlgId = digestAlgorithmIdentifierFinder.find(signAlgId);

        BcContentSignerBuilder signerBuilder = new BcECContentSignerBuilder(signAlgId, digestAlgId);

        int val = KeyUsage.cRLSign;
        val = val | KeyUsage.dataEncipherment;
        val = val | KeyUsage.decipherOnly;
        val = val | KeyUsage.digitalSignature;
        val = val | KeyUsage.encipherOnly;
        val = val | KeyUsage.keyAgreement;
        val = val | KeyUsage.keyEncipherment;
        val = val | KeyUsage.nonRepudiation;
        myCertificateGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(val));

        myCertificateGenerator.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        myCertificateGenerator.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));


        X509CertificateHolder holder = myCertificateGenerator.build(signerBuilder.build(privateKey));

        return holder;
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());
        Test test = new GOST3410_2012CMSTest();
        TestResult result = test.perform();
        System.out.println(result);
    }
}
