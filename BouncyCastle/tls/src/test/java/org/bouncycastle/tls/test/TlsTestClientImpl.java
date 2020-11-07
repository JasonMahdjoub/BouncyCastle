package com.distrimind.bouncycastle.tls.test;

import java.io.IOException;
import java.io.PrintStream;
import java.security.SecureRandom;
import java.util.Hashtable;
import java.util.Vector;

import com.distrimind.bouncycastle.asn1.ASN1EncodableVector;
import com.distrimind.bouncycastle.asn1.ASN1Encoding;
import com.distrimind.bouncycastle.asn1.DERBitString;
import com.distrimind.bouncycastle.asn1.DERSequence;
import com.distrimind.bouncycastle.asn1.x509.Certificate;
import com.distrimind.bouncycastle.tls.AlertDescription;
import com.distrimind.bouncycastle.tls.AlertLevel;
import com.distrimind.bouncycastle.tls.CertificateEntry;
import com.distrimind.bouncycastle.tls.CertificateRequest;
import com.distrimind.bouncycastle.tls.ChannelBinding;
import com.distrimind.bouncycastle.tls.CipherSuite;
import com.distrimind.bouncycastle.tls.ClientCertificateType;
import com.distrimind.bouncycastle.tls.ConnectionEnd;
import com.distrimind.bouncycastle.tls.DefaultTlsClient;
import com.distrimind.bouncycastle.tls.ProtocolVersion;
import com.distrimind.bouncycastle.tls.SignatureAlgorithm;
import com.distrimind.bouncycastle.tls.SignatureAndHashAlgorithm;
import com.distrimind.bouncycastle.tls.TlsAuthentication;
import com.distrimind.bouncycastle.tls.TlsCredentialedSigner;
import com.distrimind.bouncycastle.tls.TlsCredentials;
import com.distrimind.bouncycastle.tls.TlsExtensionsUtils;
import com.distrimind.bouncycastle.tls.TlsFatalAlert;
import com.distrimind.bouncycastle.tls.TlsServerCertificate;
import com.distrimind.bouncycastle.tls.TlsUtils;
import com.distrimind.bouncycastle.tls.crypto.TlsCertificate;
import com.distrimind.bouncycastle.tls.crypto.TlsCrypto;
import com.distrimind.bouncycastle.tls.crypto.TlsStreamSigner;
import com.distrimind.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import com.distrimind.bouncycastle.util.Arrays;
import com.distrimind.bouncycastle.util.encoders.Hex;

class TlsTestClientImpl
    extends DefaultTlsClient
{
    private static final int[] TEST_CIPHER_SUITES = new int[]
    {
        /*
         * TLS 1.3
         */
        CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_AES_128_GCM_SHA256,

        /*
         * pre-TLS 1.3
         */
        CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
        CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
    };

    protected final TlsTestConfig config;

    protected int firstFatalAlertConnectionEnd = -1;
    protected short firstFatalAlertDescription = -1;

    byte[] tlsServerEndPoint = null;
    byte[] tlsUnique = null;

    TlsTestClientImpl(TlsTestConfig config)
    {
        super(new BcTlsCrypto(new SecureRandom()));

        this.config = config;
    }

    int getFirstFatalAlertConnectionEnd()
    {
        return firstFatalAlertConnectionEnd;
    }

    short getFirstFatalAlertDescription()
    {
        return firstFatalAlertDescription;
    }

    public TlsCrypto getCrypto()
    {
        switch (config.clientCrypto)
        {
        case TlsTestConfig.CRYPTO_JCA:
            return TlsTestSuite.JCA_CRYPTO;
        default:
            return TlsTestSuite.BC_CRYPTO;
        }
    }

    public Hashtable getClientExtensions() throws IOException
    {
        Hashtable clientExtensions = super.getClientExtensions();
        if (clientExtensions != null)
        {
            if (!config.clientSendSignatureAlgorithms)
            {
                clientExtensions.remove(TlsExtensionsUtils.EXT_signature_algorithms);
                this.supportedSignatureAlgorithms = null;
            }
            if (!config.clientSendSignatureAlgorithmsCert)
            {
                clientExtensions.remove(TlsExtensionsUtils.EXT_signature_algorithms_cert);
                this.supportedSignatureAlgorithmsCert = null;
            }
        }
        return clientExtensions;
    }

    public Vector getEarlyKeyShareGroups()
    {
        if (config.clientEmptyKeyShare)
        {
            return null;
        }

        return super.getEarlyKeyShareGroups();
    }

    public boolean isFallback()
    {
        return config.clientFallback;
    }

    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
    {
        if (alertLevel == AlertLevel.fatal && firstFatalAlertConnectionEnd == -1)
        {
            firstFatalAlertConnectionEnd = ConnectionEnd.client;
            firstFatalAlertDescription = alertDescription;
        }

        if (TlsTestConfig.DEBUG)
        {
            PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
            out.println("TLS client raised alert: " + AlertLevel.getText(alertLevel)
                + ", " + AlertDescription.getText(alertDescription));
            if (message != null)
            {
                out.println("> " + message);
            }
            if (cause != null)
            {
                cause.printStackTrace(out);
            }
        }
    }

    public void notifyAlertReceived(short alertLevel, short alertDescription)
    {
        if (alertLevel == AlertLevel.fatal && firstFatalAlertConnectionEnd == -1)
        {
            firstFatalAlertConnectionEnd = ConnectionEnd.server;
            firstFatalAlertDescription = alertDescription;
        }

        if (TlsTestConfig.DEBUG)
        {
            PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
            out.println("TLS client received alert: " + AlertLevel.getText(alertLevel)
                + ", " + AlertDescription.getText(alertDescription));
        }
    }

    public void notifyHandshakeComplete() throws IOException
    {
        super.notifyHandshakeComplete();

        tlsServerEndPoint = context.exportChannelBinding(ChannelBinding.tls_server_end_point);
        tlsUnique = context.exportChannelBinding(ChannelBinding.tls_unique);

        if (TlsTestConfig.DEBUG)
        {
            System.out.println("TLS client reports 'tls-server-end-point' = " + hex(tlsServerEndPoint));
            System.out.println("TLS client reports 'tls-unique' = " + hex(tlsUnique));
        }
    }

    public void notifyServerVersion(ProtocolVersion serverVersion) throws IOException
    {
        super.notifyServerVersion(serverVersion);

        if (TlsTestConfig.DEBUG)
        {
            System.out.println("TLS client negotiated " + serverVersion);
        }
    }

    public TlsAuthentication getAuthentication()
        throws IOException
    {
        return new TlsAuthentication()
        {
            public void notifyServerCertificate(TlsServerCertificate serverCertificate)
                throws IOException
            {
                TlsCertificate[] chain = serverCertificate.getCertificate().getCertificateList();

                if (TlsTestConfig.DEBUG)
                {
                    System.out.println("TLS client received server certificate chain of length " + chain.length);
                    for (int i = 0; i != chain.length; i++)
                    {
                        Certificate entry = Certificate.getInstance(chain[i].getEncoded());
                        // TODO Create fingerprint based on certificate signature algorithm digest
                        System.out.println("    fingerprint:SHA-256 " + TlsTestUtils.fingerprint(entry) + " ("
                            + entry.getSubject() + ")");
                    }
                }

                boolean isEmpty = serverCertificate == null || serverCertificate.getCertificate() == null
                    || serverCertificate.getCertificate().isEmpty();

                if (isEmpty)
                {
                    throw new TlsFatalAlert(AlertDescription.bad_certificate);
                }

                String[] trustedCertResources = new String[]{ "x509-server-dsa.pem", "x509-server-ecdh.pem",
                    "x509-server-ecdsa.pem", "x509-server-ed25519.pem", "x509-server-ed448.pem",
                    "x509-server-rsa_pss_256.pem", "x509-server-rsa_pss_384.pem", "x509-server-rsa_pss_512.pem",
                    "x509-server-rsa-enc.pem", "x509-server-rsa-sign.pem" };

                TlsCertificate[] certPath = TlsTestUtils.getTrustedCertPath(context.getCrypto(), chain[0],
                    trustedCertResources);

                if (null == certPath)
                {
                    throw new TlsFatalAlert(AlertDescription.bad_certificate);
                }

                if (config.clientCheckSigAlgOfServerCerts)
                {
                    TlsUtils.checkPeerSigAlgs(context, certPath);
                }
            }

            public TlsCredentials getClientCredentials(CertificateRequest certificateRequest)
                throws IOException
            {
                if (config.serverCertReq == TlsTestConfig.SERVER_CERT_REQ_NONE)
                {
                    throw new IllegalStateException();
                }
                if (config.clientAuth == TlsTestConfig.CLIENT_AUTH_NONE)
                {
                    return null;
                }

                boolean isTLSv13 = TlsUtils.isTLSv13(context);

                if (!isTLSv13)
                {
                    short[] certificateTypes = certificateRequest.getCertificateTypes();
                    if (certificateTypes == null || !Arrays.contains(certificateTypes, ClientCertificateType.rsa_sign))
                    {
                        return null;
                    }
                }

                Vector supportedSigAlgs = certificateRequest.getSupportedSignatureAlgorithms();
                if (supportedSigAlgs != null && config.clientAuthSigAlg != null)
                {
                    supportedSigAlgs = new Vector(1);
                    supportedSigAlgs.addElement(config.clientAuthSigAlg);
                }

                // TODO[tls13] Check also supportedSigAlgsCert against the chain signature(s)

                final TlsCredentialedSigner signerCredentials = TlsTestUtils.loadSignerCredentials(context,
                    supportedSigAlgs, SignatureAlgorithm.rsa, "x509-client-rsa.pem", "x509-client-key-rsa.pem");

                if (config.clientAuth == TlsTestConfig.CLIENT_AUTH_VALID)
                {
                    return signerCredentials;
                }

                return new TlsCredentialedSigner()
                {
                    public byte[] generateRawSignature(byte[] hash) throws IOException
                    {
                        byte[] sig = signerCredentials.generateRawSignature(hash);

                        if (config.clientAuth == TlsTestConfig.CLIENT_AUTH_INVALID_VERIFY)
                        {
                            sig = corruptBit(sig);
                        }

                        return sig;
                    }

                    public com.distrimind.bouncycastle.tls.Certificate getCertificate()
                    {
                        com.distrimind.bouncycastle.tls.Certificate cert = signerCredentials.getCertificate();

                        if (config.clientAuth == TlsTestConfig.CLIENT_AUTH_INVALID_CERT)
                        {
                            cert = corruptCertificate(context.getCrypto(), cert);
                        }

                        return cert;
                    }

                    public SignatureAndHashAlgorithm getSignatureAndHashAlgorithm()
                    {
                        return signerCredentials.getSignatureAndHashAlgorithm();
                    }

                    public TlsStreamSigner getStreamSigner() throws IOException
                    {
                        return null;
                    }
                };
            }
        };
    }

    protected com.distrimind.bouncycastle.tls.Certificate corruptCertificate(TlsCrypto crypto, com.distrimind.bouncycastle.tls.Certificate cert)
    {
        CertificateEntry[] certEntryList = cert.getCertificateEntryList();
        try
        {
            CertificateEntry ee = certEntryList[0];
            TlsCertificate corruptCert = corruptCertificateSignature(crypto, ee.getCertificate());
            certEntryList[0] = new CertificateEntry(corruptCert, ee.getExtensions());
        }
        catch (IOException e)
        {
            throw new RuntimeException(e);
        }
        return new com.distrimind.bouncycastle.tls.Certificate(cert.getCertificateRequestContext(), certEntryList);
    }

    protected TlsCertificate corruptCertificateSignature(TlsCrypto crypto, TlsCertificate tlsCertificate) throws IOException
    {
        Certificate cert = Certificate.getInstance(tlsCertificate.getEncoded());

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(cert.getTBSCertificate());
        v.add(cert.getSignatureAlgorithm());
        v.add(corruptSignature(cert.getSignature()));

        return crypto.createCertificate(Certificate.getInstance(new DERSequence(v)).getEncoded(ASN1Encoding.DER));
    }

    protected DERBitString corruptSignature(DERBitString bs)
    {
        return new DERBitString(corruptBit(bs.getOctets()));
    }

    protected byte[] corruptBit(byte[] bs)
    {
        bs = Arrays.clone(bs);

        // Flip a random bit
        int bit = context.getCrypto().getSecureRandom().nextInt(bs.length << 3);
        bs[bit >>> 3] ^= (1 << (bit & 7));

        return bs;
    }

    protected int[] getSupportedCipherSuites()
    {
        return TlsUtils.getSupportedCipherSuites(getCrypto(), TEST_CIPHER_SUITES);
    }

    protected ProtocolVersion[] getSupportedVersions()
    {
        if (null != config.clientSupportedVersions)
        {
            return config.clientSupportedVersions;
        }

        return super.getSupportedVersions();
    }

    protected String hex(byte[] data)
    {
        return data == null ? "(null)" : Hex.toHexString(data);
    }
}
