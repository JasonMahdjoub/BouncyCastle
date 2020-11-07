package com.distrimind.bouncycastle.tls.test;

import java.io.IOException;
import java.io.PrintStream;
import java.security.SecureRandom;
import java.util.Hashtable;
import java.util.Vector;

import com.distrimind.bouncycastle.asn1.x509.Certificate;
import com.distrimind.bouncycastle.tls.AlertDescription;
import com.distrimind.bouncycastle.tls.AlertLevel;
import com.distrimind.bouncycastle.tls.BasicTlsPSKIdentity;
import com.distrimind.bouncycastle.tls.ChannelBinding;
import com.distrimind.bouncycastle.tls.MaxFragmentLength;
import com.distrimind.bouncycastle.tls.PSKTlsClient;
import com.distrimind.bouncycastle.tls.ProtocolName;
import com.distrimind.bouncycastle.tls.ProtocolVersion;
import com.distrimind.bouncycastle.tls.ServerOnlyTlsAuthentication;
import com.distrimind.bouncycastle.tls.TlsAuthentication;
import com.distrimind.bouncycastle.tls.TlsExtensionsUtils;
import com.distrimind.bouncycastle.tls.TlsFatalAlert;
import com.distrimind.bouncycastle.tls.TlsPSKIdentity;
import com.distrimind.bouncycastle.tls.TlsServerCertificate;
import com.distrimind.bouncycastle.tls.TlsSession;
import com.distrimind.bouncycastle.tls.TlsUtils;
import com.distrimind.bouncycastle.tls.crypto.TlsCertificate;
import com.distrimind.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import com.distrimind.bouncycastle.util.Arrays;
import com.distrimind.bouncycastle.util.Strings;
import com.distrimind.bouncycastle.util.encoders.Hex;

class MockPSKTlsClient
    extends PSKTlsClient
{
    TlsSession session;

    MockPSKTlsClient(TlsSession session)
    {
        this(session, new BasicTlsPSKIdentity("client", Strings.toUTF8ByteArray("TLS_TEST_PSK")));
    }

    MockPSKTlsClient(TlsSession session, TlsPSKIdentity pskIdentity)
    {
        super(new BcTlsCrypto(new SecureRandom()), pskIdentity);

        this.session = session;
    }

    protected Vector getProtocolNames()
    {
        Vector protocolNames = new Vector();
        protocolNames.addElement(ProtocolName.HTTP_1_1);
        protocolNames.addElement(ProtocolName.HTTP_2_TLS);
        return protocolNames;
    }

    public TlsSession getSessionToResume()
    {
        return this.session;
    }

    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
    {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("TLS-PSK client raised alert: " + AlertLevel.getText(alertLevel)
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

    public void notifyAlertReceived(short alertLevel, short alertDescription)
    {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("TLS-PSK client received alert: " + AlertLevel.getText(alertLevel)
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

        System.out.println("TLS-PSK client negotiated " + serverVersion);
    }

    public TlsAuthentication getAuthentication() throws IOException
    {
        return new ServerOnlyTlsAuthentication()
        {
            public void notifyServerCertificate(TlsServerCertificate serverCertificate) throws IOException
            {
                TlsCertificate[] chain = serverCertificate.getCertificate().getCertificateList();

                System.out.println("TLS-PSK client received server certificate chain of length " + chain.length);
                for (int i = 0; i != chain.length; i++)
                {
                    Certificate entry = Certificate.getInstance(chain[i].getEncoded());
                    // TODO Create fingerprint based on certificate signature algorithm digest
                    System.out.println("    fingerprint:SHA-256 " + TlsTestUtils.fingerprint(entry) + " ("
                        + entry.getSubject() + ")");
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

                TlsUtils.checkPeerSigAlgs(context, certPath);
            }
        };
    }

    public void notifyHandshakeComplete() throws IOException
    {
        super.notifyHandshakeComplete();

        ProtocolName protocolName = context.getSecurityParametersConnection().getApplicationProtocol();
        if (protocolName != null)
        {
            System.out.println("Client ALPN: " + protocolName.getUtf8Decoding());
        }

        TlsSession newSession = context.getSession();
        if (newSession != null)
        {
            if (newSession.isResumable())
            {
                byte[] newSessionID = newSession.getSessionID();
                String hex = Hex.toHexString(newSessionID);

                if (this.session != null && Arrays.areEqual(this.session.getSessionID(), newSessionID))
                {
                    System.out.println("Client resumed session: " + hex);
                }
                else
                {
                    System.out.println("Client established session: " + hex);
                }

                this.session = newSession;
            }

            byte[] tlsServerEndPoint = context.exportChannelBinding(ChannelBinding.tls_server_end_point);
            if (null != tlsServerEndPoint)
            {
                System.out.println("Client 'tls-server-end-point': " + hex(tlsServerEndPoint));
            }

            byte[] tlsUnique = context.exportChannelBinding(ChannelBinding.tls_unique);
            System.out.println("Client 'tls-unique': " + hex(tlsUnique));
        }
    }

    protected String hex(byte[] data)
    {
        return data == null ? "(null)" : Hex.toHexString(data);
    }

    protected ProtocolVersion[] getSupportedVersions()
    {
        return ProtocolVersion.TLSv12.only();
    }
}
