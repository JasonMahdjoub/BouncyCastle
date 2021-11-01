package com.distrimind.bouncycastle.tls;

import com.distrimind.bouncycastle.tls.crypto.TlsCrypto;

class TlsServerContextImpl
    extends AbstractTlsContext
    implements TlsServerContext
{
    TlsServerContextImpl(TlsCrypto crypto)
    {
        super(crypto, ConnectionEnd.server);
    }

    public boolean isServer()
    {
        return true;
    }
}
