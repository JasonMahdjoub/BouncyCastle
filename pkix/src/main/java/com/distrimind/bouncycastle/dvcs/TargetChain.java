package com.distrimind.bouncycastle.dvcs;

import com.distrimind.bouncycastle.asn1.dvcs.TargetEtcChain;

public class TargetChain
{
    private final TargetEtcChain certs;

    public TargetChain(TargetEtcChain certs)
    {
        this.certs = certs;
    }

    public TargetEtcChain toASN1Structure()
    {
        return certs;
    }
}
