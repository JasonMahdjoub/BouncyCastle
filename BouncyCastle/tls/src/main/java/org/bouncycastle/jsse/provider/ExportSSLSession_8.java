package com.distrimind.bouncycastle.jsse.provider;

import java.util.List;

import javax.net.ssl.SNIServerName;

import com.distrimind.bouncycastle.jsse.BCExtendedSSLSession;

class ExportSSLSession_8
    extends ExportSSLSession_7
{
    ExportSSLSession_8(BCExtendedSSLSession sslSession)
    {
        super(sslSession);
    }

    public List<SNIServerName> getRequestedServerNames()
    {
        return JsseUtils_8.exportSNIServerNames(sslSession.getRequestedServerNames());
    }
}
