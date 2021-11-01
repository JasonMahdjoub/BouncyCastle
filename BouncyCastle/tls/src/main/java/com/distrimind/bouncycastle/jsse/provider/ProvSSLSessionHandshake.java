package com.distrimind.bouncycastle.jsse.provider;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Vector;

import com.distrimind.bouncycastle.jsse.BCSNIServerName;
import com.distrimind.bouncycastle.tls.ProtocolVersion;
import com.distrimind.bouncycastle.tls.SecurityParameters;
import com.distrimind.bouncycastle.tls.ServerName;

class ProvSSLSessionHandshake
    extends ProvSSLSessionBase
{
    protected final SecurityParameters securityParameters;
    protected final JsseSecurityParameters jsseSecurityParameters;

    ProvSSLSessionHandshake(ProvSSLSessionContext sslSessionContext, String peerHost, int peerPort,
        SecurityParameters securityParameters, JsseSecurityParameters jsseSecurityParameters)
    {
        super(sslSessionContext, peerHost, peerPort);

        this.securityParameters = securityParameters;
        this.jsseSecurityParameters = jsseSecurityParameters;
    }

    String getApplicationProtocol()
    {
        return JsseUtils.getApplicationProtocol(securityParameters);
    }

    @Override
    protected int getCipherSuiteTLS()
    {
        return securityParameters.getCipherSuite();
    }

    @Override
    protected byte[] getIDArray()
    {
        return securityParameters.getSessionID();
    }

    @Override
    protected JsseSecurityParameters getJsseSecurityParameters()
    {
        return jsseSecurityParameters;
    }

    @Override
    protected JsseSessionParameters getJsseSessionParameters()
    {
        return null;
    }

    @Override
    protected com.distrimind.bouncycastle.tls.Certificate getLocalCertificateTLS()
    {
        return securityParameters.getLocalCertificate();
    }

    @Override
    public String[] getLocalSupportedSignatureAlgorithms()
    {
        return SignatureSchemeInfo.getJcaSignatureAlgorithms(jsseSecurityParameters.localSigSchemesCert);
    }

    @Override
    public String[] getLocalSupportedSignatureAlgorithmsBC()
    {
        return SignatureSchemeInfo.getJcaSignatureAlgorithmsBC(jsseSecurityParameters.localSigSchemesCert);
    }

    @Override
    protected com.distrimind.bouncycastle.tls.Certificate getPeerCertificateTLS()
    {
        return securityParameters.getPeerCertificate();
    }

    @Override
    public String[] getPeerSupportedSignatureAlgorithms()
    {
        return SignatureSchemeInfo.getJcaSignatureAlgorithms(jsseSecurityParameters.peerSigSchemesCert);
    }

    @Override
    public String[] getPeerSupportedSignatureAlgorithmsBC()
    {
        return SignatureSchemeInfo.getJcaSignatureAlgorithmsBC(jsseSecurityParameters.peerSigSchemesCert);
    }

    @Override
    protected ProtocolVersion getProtocolTLS()
    {
        return securityParameters.getNegotiatedVersion();
    }

    @Override
    public List<BCSNIServerName> getRequestedServerNames()
    {
        @SuppressWarnings("unchecked")
        Vector<ServerName> clientServerNames = securityParameters.getClientServerNames();

        return JsseUtils.convertSNIServerNames(clientServerNames);
    }

    @Override
    public List<byte[]> getStatusResponses()
    {
        List<byte[]> statusResponses = jsseSecurityParameters.statusResponses;
        if (null == statusResponses || statusResponses.isEmpty())
        {
            return Collections.emptyList();
        }

        ArrayList<byte[]> result = new ArrayList<byte[]>(statusResponses.size());
        for (byte[] statusResponse : statusResponses)
        {
            result.add(statusResponse.clone());
        }
        return Collections.unmodifiableList(result);
    }
}
