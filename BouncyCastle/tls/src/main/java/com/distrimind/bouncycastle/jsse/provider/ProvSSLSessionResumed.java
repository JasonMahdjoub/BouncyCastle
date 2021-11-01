package com.distrimind.bouncycastle.jsse.provider;

import com.distrimind.bouncycastle.tls.ProtocolVersion;
import com.distrimind.bouncycastle.tls.SecurityParameters;
import com.distrimind.bouncycastle.tls.SessionParameters;
import com.distrimind.bouncycastle.tls.TlsSession;

class ProvSSLSessionResumed
    extends ProvSSLSessionHandshake
{
    protected final TlsSession tlsSession;
    protected final SessionParameters sessionParameters;
    protected final JsseSessionParameters jsseSessionParameters;

    ProvSSLSessionResumed(ProvSSLSessionContext sslSessionContext, String peerHost, int peerPort,
        SecurityParameters securityParameters, JsseSecurityParameters jsseSecurityParameters, TlsSession tlsSession,
        JsseSessionParameters jsseSessionParameters)
    {
        super(sslSessionContext, peerHost, peerPort, securityParameters, jsseSecurityParameters);

        this.tlsSession = tlsSession;
        this.sessionParameters = tlsSession.exportSessionParameters();
        this.jsseSessionParameters = jsseSessionParameters;
    }

    @Override
    protected int getCipherSuiteTLS()
    {
        return sessionParameters.getCipherSuite();
    }

    @Override
    protected byte[] getIDArray()
    {
        return tlsSession.getSessionID();
    }

    @Override
    protected JsseSessionParameters getJsseSessionParameters()
    {
        return jsseSessionParameters;
    }

    @Override
    protected com.distrimind.bouncycastle.tls.Certificate getLocalCertificateTLS()
    {
        return sessionParameters.getLocalCertificate();
    }

    @Override
    protected com.distrimind.bouncycastle.tls.Certificate getPeerCertificateTLS()
    {
        return sessionParameters.getPeerCertificate();
    }

    @Override
    protected ProtocolVersion getProtocolTLS()
    {
        return sessionParameters.getNegotiatedVersion();
    }

    public void invalidate()
    {
        super.invalidate();

        tlsSession.invalidate();
    }

    public boolean isValid()
    {
        return super.isValid() && tlsSession.isResumable();
    }
}
