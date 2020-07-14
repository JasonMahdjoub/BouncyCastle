package com.distrimind.bouncycastle.jsse.provider;

import java.util.List;

import com.distrimind.bouncycastle.jsse.BCSNIServerName;
import com.distrimind.bouncycastle.tls.CipherSuite;
import com.distrimind.bouncycastle.tls.ProtocolVersion;
import com.distrimind.bouncycastle.tls.SessionParameters;
import com.distrimind.bouncycastle.tls.TlsSession;

class ProvSSLSession
    extends ProvSSLSessionBase
{
    // TODO[jsse] Ensure this behaves according to the javadoc for SSLSocket.getSession and SSLEngine.getSession
    // TODO[jsse] This would make more sense as a ProvSSLSessionHandshake
    static final ProvSSLSession NULL_SESSION = new ProvSSLSession(null, null, -1, null,
        new JsseSessionParameters(null));

    protected final TlsSession tlsSession;
    protected final SessionParameters sessionParameters;
    protected final JsseSessionParameters jsseSessionParameters;

    ProvSSLSession(ProvSSLSessionContext sslSessionContext, String peerHost, int peerPort, TlsSession tlsSession,
        JsseSessionParameters jsseSessionParameters)
    {
        super(sslSessionContext, peerHost, peerPort);

        this.tlsSession = tlsSession;
        this.sessionParameters = tlsSession == null ? null : tlsSession.exportSessionParameters();
        this.jsseSessionParameters = jsseSessionParameters;
    }

    @Override
    protected int getCipherSuiteTLS()
    {
        return null == sessionParameters ? CipherSuite.TLS_NULL_WITH_NULL_NULL : sessionParameters.getCipherSuite();
    }

    @Override
    protected byte[] getIDArray()
    {
        return null == tlsSession ? null : tlsSession.getSessionID();
    }

    @Override
    protected JsseSecurityParameters getJsseSecurityParameters()
    {
        return null;
    }

    @Override
    protected JsseSessionParameters getJsseSessionParameters()
    {
        return jsseSessionParameters;
    }

    @Override
    protected com.distrimind.bouncycastle.tls.Certificate getLocalCertificateTLS()
    {
        return null == sessionParameters ? null : sessionParameters.getLocalCertificate();
    }

    @Override
    public String[] getLocalSupportedSignatureAlgorithms()
    {
        // TODO Should we store these in SessionParameters?
        return null;
    }

    @Override
    protected com.distrimind.bouncycastle.tls.Certificate getPeerCertificateTLS()
    {
        return null == sessionParameters ? null : sessionParameters.getPeerCertificate();
    }

    @Override
    public String[] getPeerSupportedSignatureAlgorithms()
    {
        // TODO Should we store these in SessionParameters?
        return null;
    }

    @Override
    protected ProtocolVersion getProtocolTLS()
    {
        return null == sessionParameters ? null : sessionParameters.getNegotiatedVersion();
    }

    @Override
    public List<BCSNIServerName> getRequestedServerNames()
    {
        throw new UnsupportedOperationException();
    }

    TlsSession getTlsSession()
    {
        return tlsSession;
    }

    public void invalidate()
    {
        super.invalidate();

        if (null != tlsSession)
        {
            tlsSession.invalidate();
        }
    }

    public boolean isValid()
    {
        return super.isValid() && null != tlsSession && tlsSession.isResumable();
    }
}
