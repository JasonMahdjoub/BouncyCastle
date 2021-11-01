package com.distrimind.bouncycastle.tls.test;

import java.io.IOException;
import java.io.PrintStream;
import java.security.SecureRandom;

import com.distrimind.bouncycastle.tls.AlertDescription;
import com.distrimind.bouncycastle.tls.AlertLevel;
import com.distrimind.bouncycastle.tls.ChannelBinding;
import com.distrimind.bouncycastle.tls.PSKTlsServer;
import com.distrimind.bouncycastle.tls.ProtocolVersion;
import com.distrimind.bouncycastle.tls.TlsCredentialedDecryptor;
import com.distrimind.bouncycastle.tls.TlsPSKIdentityManager;
import com.distrimind.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import com.distrimind.bouncycastle.util.Strings;
import com.distrimind.bouncycastle.util.encoders.Hex;

class MockPSKDTLSServer
    extends PSKTlsServer
{
    MockPSKDTLSServer()
    {
        super(new BcTlsCrypto(new SecureRandom()), new MyIdentityManager());
    }

    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
    {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("DTLS-PSK server raised alert: " + AlertLevel.getText(alertLevel)
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
        out.println("DTLS-PSK server received alert: " + AlertLevel.getText(alertLevel)
            + ", " + AlertDescription.getText(alertDescription));
    }

    public ProtocolVersion getServerVersion() throws IOException
    {
        ProtocolVersion serverVersion = super.getServerVersion();

        System.out.println("DTLS-PSK server negotiated " + serverVersion);

        return serverVersion;
    }

    public void notifyHandshakeComplete() throws IOException
    {
        super.notifyHandshakeComplete();

        byte[] tlsServerEndPoint = context.exportChannelBinding(ChannelBinding.tls_server_end_point);
        System.out.println("Server 'tls-server-end-point': " + hex(tlsServerEndPoint));

        byte[] tlsUnique = context.exportChannelBinding(ChannelBinding.tls_unique);
        System.out.println("Server 'tls-unique': " + hex(tlsUnique));

        byte[] pskIdentity = context.getSecurityParametersConnection().getPSKIdentity();
        if (pskIdentity != null)
        {
            String name = Strings.fromUTF8ByteArray(pskIdentity);
            System.out.println("TLS-PSK server completed handshake for PSK identity: " + name);
        }
    }

    protected TlsCredentialedDecryptor getRSAEncryptionCredentials() throws IOException
    {
        return TlsTestUtils.loadEncryptionCredentials(context, new String[]{ "x509-server-rsa-enc.pem", "x509-ca-rsa.pem" },
            "x509-server-key-rsa-enc.pem");
    }

    protected String hex(byte[] data)
    {
        return data == null ? "(null)" : Hex.toHexString(data);
    }

    protected ProtocolVersion[] getSupportedVersions()
    {
        return ProtocolVersion.DTLSv12.only();
    }

    static class MyIdentityManager
        implements TlsPSKIdentityManager
    {
        public byte[] getHint()
        {
            return Strings.toUTF8ByteArray("hint");
        }

        public byte[] getPSK(byte[] identity)
        {
            if (identity != null)
            {
                String name = Strings.fromUTF8ByteArray(identity);
                if (name.equals("client"))
                {
                    return Strings.toUTF8ByteArray("TLS_TEST_PSK");
                }
            }
            return null;
        }
    }
}
