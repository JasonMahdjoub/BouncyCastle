package com.distrimind.bouncycastle.tls.crypto.impl.bc;

import com.distrimind.bouncycastle.tls.crypto.TlsAgreement;
import com.distrimind.bouncycastle.tls.crypto.TlsECDomain;

public class BcX448Domain implements TlsECDomain
{
    protected final BcTlsCrypto crypto;

    public BcX448Domain(BcTlsCrypto crypto)
    {
        this.crypto = crypto;
    }

    public TlsAgreement createECDH()
    {
        return new BcX448(crypto);
    }
}
