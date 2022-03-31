package com.distrimind.bouncycastle.tls.test;

import java.io.InputStream;
import java.io.OutputStream;

import com.distrimind.bouncycastle.tls.TlsServerProtocol;

class TlsTestServerProtocol extends TlsServerProtocol
{
    protected final TlsTestConfig config;

    public TlsTestServerProtocol(InputStream input, OutputStream output, TlsTestConfig config)
    {
        super(input, output);

        this.config = config;
    }
}
