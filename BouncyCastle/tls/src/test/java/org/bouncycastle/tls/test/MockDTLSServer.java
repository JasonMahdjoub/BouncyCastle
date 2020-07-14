package com.distrimind.bouncycastle.tls.test;

import java.io.IOException;
import java.io.PrintStream;
import java.security.SecureRandom;
import java.util.Vector;

import com.distrimind.bouncycastle.asn1.x500.X500Name;
import com.distrimind.bouncycastle.asn1.x509.Certificate;
import com.distrimind.bouncycastle.tls.AlertDescription;
import com.distrimind.bouncycastle.tls.AlertLevel;
import com.distrimind.bouncycastle.tls.CertificateRequest;
import com.distrimind.bouncycastle.tls.ClientCertificateType;
import com.distrimind.bouncycastle.tls.DefaultTlsServer;
import com.distrimind.bouncycastle.tls.ProtocolVersion;
import com.distrimind.bouncycastle.tls.SignatureAlgorithm;
import com.distrimind.bouncycastle.tls.TlsCredentialedDecryptor;
import com.distrimind.bouncycastle.tls.TlsCredentialedSigner;
import com.distrimind.bouncycastle.tls.TlsUtils;
import com.distrimind.bouncycastle.tls.crypto.TlsCertificate;
import com.distrimind.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

public class MockDTLSServer
    extends DefaultTlsServer
{
    MockDTLSServer()
    {
        super(new BcTlsCrypto(new SecureRandom()));
    }

    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
    {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("DTLS server raised alert: " + AlertLevel.getText(alertLevel)
            + ", " + AlertDescription.getText(alertDescription));
        if (message != null)
        {
            out.println(message);
        }
        if (cause != null)
        {
            cause.printStackTrace(out);
        }
    }

    public void notifyAlertReceived(short alertLevel, short alertDescription)
    {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("DTLS server received alert: " + AlertLevel.getText(alertLevel)
            + ", " + AlertDescription.getText(alertDescription));
    }

    public CertificateRequest getCertificateRequest() throws IOException
    {
        short[] certificateTypes = new short[]{ ClientCertificateType.rsa_sign,
            ClientCertificateType.dss_sign, ClientCertificateType.ecdsa_sign };

        Vector serverSigAlgs = null;
        if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(context.getServerVersion()))
        {
            serverSigAlgs = TlsUtils.getDefaultSupportedSignatureAlgorithms(context);
        }

        Vector certificateAuthorities = new Vector();
//      certificateAuthorities.addElement(TlsTestUtils.loadBcCertificateResource("x509-ca-dsa.pem").getSubject());
//      certificateAuthorities.addElement(TlsTestUtils.loadBcCertificateResource("x509-ca-ecdsa.pem").getSubject());
//      certificateAuthorities.addElement(TlsTestUtils.loadBcCertificateResource("x509-ca-rsa.pem").getSubject());

        // All the CA certificates are currently configured with this subject
        certificateAuthorities.addElement(new X500Name("CN=BouncyCastle TLS Test CA"));

        return new CertificateRequest(certificateTypes, serverSigAlgs, certificateAuthorities);
    }

    public void notifyClientCertificate(com.distrimind.bouncycastle.tls.Certificate clientCertificate)
        throws IOException
    {
        TlsCertificate[] chain = clientCertificate.getCertificateList();
        System.out.println("DTLS server received client certificate chain of length " + chain.length);
        for (int i = 0; i != chain.length; i++)
        {
            Certificate entry = Certificate.getInstance(chain[i].getEncoded());
            // TODO Create fingerprint based on certificate signature algorithm digest
            System.out.println("    fingerprint:SHA-256 " + TlsTestUtils.fingerprint(entry) + " (" + entry.getSubject()
                + ")");
        }
    }

    protected TlsCredentialedDecryptor getRSAEncryptionCredentials()
        throws IOException
    {
        return TlsTestUtils.loadEncryptionCredentials(context, new String[]{"x509-server-rsa-enc.pem", "x509-ca-rsa.pem"},
            "x509-server-key-rsa-enc.pem");
    }

    protected TlsCredentialedSigner getRSASignerCredentials() throws IOException
    {
        Vector clientSigAlgs = context.getSecurityParametersHandshake().getClientSigAlgs();
        return TlsTestUtils.loadSignerCredentialsServer(context, clientSigAlgs, SignatureAlgorithm.rsa);
    }

    protected ProtocolVersion[] getSupportedVersions()
    {
        return ProtocolVersion.DTLSv12.downTo(ProtocolVersion.DTLSv10);
    }
}
