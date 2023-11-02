package com.distrimind.bouncycastle.test.est;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

import com.distrimind.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import com.distrimind.bouncycastle.asn1.x500.X500Name;
import com.distrimind.bouncycastle.cert.X509CertificateHolder;
import com.distrimind.bouncycastle.est.CACertsResponse;
import com.distrimind.bouncycastle.est.ESTException;
import com.distrimind.bouncycastle.est.ESTService;
import com.distrimind.bouncycastle.est.EnrollmentResponse;
import com.distrimind.bouncycastle.est.jcajce.JcaJceUtils;
import com.distrimind.bouncycastle.est.jcajce.JsseESTServiceBuilder;
import com.distrimind.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import com.distrimind.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import com.distrimind.bouncycastle.pkcs.PKCS10CertificationRequest;
import com.distrimind.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import com.distrimind.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import com.distrimind.bouncycastle.util.io.Streams;
import com.distrimind.bouncycastle.util.test.SimpleTest;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

public class TestServerKeyGeneration
    extends SimpleTest
{


    @Before
    public void before()
    {
        ESTTestUtils.ensureProvider();
    }

    public String getName()
    {
        return "test against globalsign est server";
    }

    public void performTest()
        throws Exception
    {
        testServerGenWithoutEncryption();
    }


    @Test
    public void testServerGenWithoutEncryption()
        throws Exception
    {
        //
        // This test requires an instance of https://github.com/globalsign/est to be running.
        // We will try and fetch the CA certs and if that is not possible the test will skip.
        //

        Object[] caCerts = null;

        try
        {
            ESTService svc = new JsseESTServiceBuilder("localhost:8443", JcaJceUtils.getTrustAllTrustManager()).build();
            CACertsResponse resp = svc.getCACerts();
            caCerts = ESTService.storeToArray(resp.getCertificateStore());
        }
        catch (ESTException ex)
        {
            // Skip if server cannot be reached.
            Assume.assumeNoException(ex);
        }


        ESTService est = new JsseESTServiceBuilder(
            "localhost:8443", JcaJceUtils.getCertPathTrustManager(
            ESTTestUtils.toTrustAnchor(caCerts), null)
        ).withProvider(BouncyCastleJsseProvider.PROVIDER_NAME).withTLSVersion("TLS").build();

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair enrollmentPair = kpg.generateKeyPair();

        PKCS10CertificationRequestBuilder pkcs10Builder = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=Test"), enrollmentPair.getPublic());


        PKCS10CertificationRequest csr = pkcs10Builder.build(
            new JcaContentSignerBuilder("SHA256WITHECDSA").setProvider("BC").build(enrollmentPair.getPrivate()));

        SecureRandom nonceRandom = new SecureRandom();


        // new JcaHttpAuthBuilder("estuser", "estpwd".toCharArray()).setNonceGenerator(nonceRandom).setProvider("BC").build()
        try
        {
            EnrollmentResponse enr = est.simpleEnrollWithServersideCreation(csr, null);
            PrivateKeyInfo pki = enr.getPrivateKeyInfo();

            //
            // Not testing if the server is generating sane keys.
            // Did we get a private key info and at least one certificate
            //
            if (pki == null)
            {
                fail("expecting pki");
            }

            X509CertificateHolder enrolledAsHolder = ESTService.storeToArray(enr.getStore())[0];
            if (enrolledAsHolder == null)
            {
                fail("expecting certificate");
            }
        }
        catch (ESTException estException)
        {
            System.out.println();
            Streams.pipeAll(estException.getBody(), System.out);
            System.out.println();
        }
        System.out.println();
    }


    public static void main(String[] args)
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        runTest(new TestServerKeyGeneration());
    }

}
