package org.bouncycastle.bccrypto.tls.test;

import java.security.SecureRandom;

import org.bouncycastle.bccrypto.tls.DTLSServerProtocol;

class DTLSTestServerProtocol extends DTLSServerProtocol
{
    protected final TlsTestConfig config;

    public DTLSTestServerProtocol(SecureRandom secureRandom, TlsTestConfig config)
    {
        super(secureRandom);

        this.config = config;
    }
}
