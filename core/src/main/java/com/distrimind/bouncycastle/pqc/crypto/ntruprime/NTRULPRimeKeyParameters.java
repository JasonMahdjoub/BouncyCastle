package com.distrimind.bouncycastle.pqc.crypto.ntruprime;

import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class NTRULPRimeKeyParameters
    extends AsymmetricKeyParameter
{
    private final NTRULPRimeParameters params;

    public NTRULPRimeKeyParameters(boolean privateKey, NTRULPRimeParameters params)
    {
        super(privateKey);
        this.params = params;
    }

    public NTRULPRimeParameters getParameters()
    {
        return params;
    }
}
