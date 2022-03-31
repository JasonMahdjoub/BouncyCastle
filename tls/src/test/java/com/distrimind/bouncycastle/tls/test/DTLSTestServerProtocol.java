package com.distrimind.bouncycastle.tls.test;

import com.distrimind.bouncycastle.tls.DTLSServerProtocol;

class DTLSTestServerProtocol extends DTLSServerProtocol
{
    protected final TlsTestConfig config;

    public DTLSTestServerProtocol(TlsTestConfig config)
    {
        super();

        this.config = config;
    }
}
