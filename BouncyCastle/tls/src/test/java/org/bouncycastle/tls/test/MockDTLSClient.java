package com.distrimind.bouncycastle.tls.test;

import java.io.IOException;
import java.io.PrintStream;
import java.security.SecureRandom;
import java.util.Hashtable;

import com.distrimind.bouncycastle.asn1.x509.Certificate;
import com.distrimind.bouncycastle.tls.AlertDescription;
import com.distrimind.bouncycastle.tls.AlertLevel;
import com.distrimind.bouncycastle.tls.CertificateRequest;
import com.distrimind.bouncycastle.tls.ClientCertificateType;
import com.distrimind.bouncycastle.tls.DefaultTlsClient;
import com.distrimind.bouncycastle.tls.MaxFragmentLength;
import com.distrimind.bouncycastle.tls.ProtocolVersion;
import com.distrimind.bouncycastle.tls.SignatureAlgorithm;
import com.distrimind.bouncycastle.tls.TlsAuthentication;
import com.distrimind.bouncycastle.tls.TlsCredentials;
import com.distrimind.bouncycastle.tls.TlsExtensionsUtils;
import com.distrimind.bouncycastle.tls.TlsServerCertificate;
import com.distrimind.bouncycastle.tls.TlsSession;
import com.distrimind.bouncycastle.tls.crypto.TlsCertificate;
import com.distrimind.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import com.distrimind.bouncycastle.util.Arrays;
import com.distrimind.bouncycastle.util.encoders.Hex;

public class MockDTLSClient
    extends DefaultTlsClient
{
    protected TlsSession session;

    public MockDTLSClient(TlsSession session)
    {
        super(new BcTlsCrypto(new SecureRandom()));

        this.session = session;
    }

    public TlsSession getSessionToResume()
    {
        return this.session;
    }

    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
    {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("DTLS client raised alert: " + AlertLevel.getText(alertLevel)
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
        out.println("DTLS client received alert: " + AlertLevel.getText(alertLevel)
            + ", " + AlertDescription.getText(alertDescription));
    }

    public Hashtable getClientExtensions() throws IOException
    {
        Hashtable clientExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(super.getClientExtensions());
        {
            /*
             * NOTE: If you are copying test code, do not blindly set these extensions in your own client.
             */
            TlsExtensionsUtils.addMaxFragmentLengthExtension(clientExtensions, MaxFragmentLength.pow2_9);
            TlsExtensionsUtils.addPaddingExtension(clientExtensions, context.getCrypto().getSecureRandom().nextInt(16));
            TlsExtensionsUtils.addTruncatedHMacExtension(clientExtensions);
        }
        return clientExtensions;
    }

    public void notifyServerVersion(ProtocolVersion serverVersion) throws IOException
    {
        super.notifyServerVersion(serverVersion);

        System.out.println("Negotiated " + serverVersion);
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
                System.out.println("DTLS client received server certificate chain of length " + chain.length);
                for (int i = 0; i != chain.length; i++)
                {
                    Certificate entry = Certificate.getInstance(chain[i].getEncoded());
                    // TODO Create fingerprint based on certificate signature algorithm digest
                    System.out.println("    fingerprint:SHA-256 " + TlsTestUtils.fingerprint(entry) + " ("
                        + entry.getSubject() + ")");
                }
            }

            public TlsCredentials getClientCredentials(CertificateRequest certificateRequest)
                throws IOException
            {
                short[] certificateTypes = certificateRequest.getCertificateTypes();
                if (certificateTypes == null || !Arrays.contains(certificateTypes, ClientCertificateType.rsa_sign))
                {
                    return null;
                }

                return TlsTestUtils.loadSignerCredentials(context, certificateRequest.getSupportedSignatureAlgorithms(),
                    SignatureAlgorithm.rsa, "x509-client-rsa.pem", "x509-client-key-rsa.pem");
            }
        };
    }

    public void notifyHandshakeComplete() throws IOException
    {
        super.notifyHandshakeComplete();

        TlsSession newSession = context.getResumableSession();
        if (newSession != null)
        {
            byte[] newSessionID = newSession.getSessionID();
            String hex = Hex.toHexString(newSessionID);

            if (this.session != null && Arrays.areEqual(this.session.getSessionID(), newSessionID))
            {
                System.out.println("Resumed session: " + hex);
            }
            else
            {
                System.out.println("Established session: " + hex);
            }

            this.session = newSession;
        }
    }

    protected ProtocolVersion[] getSupportedVersions()
    {
        return ProtocolVersion.DTLSv12.downTo(ProtocolVersion.DTLSv10);
    }
}
