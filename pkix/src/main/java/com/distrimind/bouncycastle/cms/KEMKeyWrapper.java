package com.distrimind.bouncycastle.cms;

import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.operator.AsymmetricKeyWrapper;

public abstract class KEMKeyWrapper
    extends AsymmetricKeyWrapper
{
    protected KEMKeyWrapper(AlgorithmIdentifier algorithmId)
    {
        super(algorithmId);
    }

    public abstract byte[] getEncapsulation();

    public abstract AlgorithmIdentifier getKdfAlgorithmIdentifier();

    public abstract int getKekLength();

    public abstract AlgorithmIdentifier getWrapAlgorithmIdentifier();
}
