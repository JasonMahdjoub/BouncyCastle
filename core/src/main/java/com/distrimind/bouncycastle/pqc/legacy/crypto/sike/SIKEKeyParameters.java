package com.distrimind.bouncycastle.pqc.legacy.crypto.sike;

import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class SIKEKeyParameters
    extends AsymmetricKeyParameter
{
    private SIKEParameters params;

    public SIKEKeyParameters(
            boolean isPrivate,
            SIKEParameters params
    )
    {
        super(isPrivate);
        this.params = params;
    }

    public SIKEParameters getParameters()
    {
        return params;
    }
}
