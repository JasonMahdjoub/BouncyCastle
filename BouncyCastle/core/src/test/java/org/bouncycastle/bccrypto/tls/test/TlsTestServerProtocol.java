package org.bouncycastle.bccrypto.tls.test;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

import org.bouncycastle.bccrypto.tls.TlsServerProtocol;

class TlsTestServerProtocol extends TlsServerProtocol
{
    protected final TlsTestConfig config;

    public TlsTestServerProtocol(InputStream input, OutputStream output, SecureRandom secureRandom, TlsTestConfig config)
    {
        super(input, output, secureRandom);

        this.config = config;
    }
}
