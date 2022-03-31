package com.distrimind.bouncycastle.jsse.provider;

import java.util.List;

import com.distrimind.bouncycastle.jsse.BCExtendedSSLSession;

class ExportSSLSession_9
    extends ExportSSLSession_8
{
    ExportSSLSession_9(BCExtendedSSLSession sslSession)
    {
        super(sslSession);
    }

    @Override
    public List<byte[]> getStatusResponses()
    {
        return sslSession.getStatusResponses();
    }
}
