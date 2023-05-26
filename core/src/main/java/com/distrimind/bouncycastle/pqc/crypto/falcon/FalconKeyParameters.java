package com.distrimind.bouncycastle.pqc.crypto.falcon;

import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class FalconKeyParameters
    extends AsymmetricKeyParameter
{

    private final FalconParameters params;

    public FalconKeyParameters(boolean isprivate, FalconParameters parameters)
    {
        super(isprivate);
        this.params = parameters;
    }

    public FalconParameters getParameters()
    {
        return params;
    }
}
