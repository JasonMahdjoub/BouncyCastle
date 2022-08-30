package com.distrimind.bouncycastle.pqc.crypto.frodo;

import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class FrodoKeyParameters
        extends AsymmetricKeyParameter
{
    private FrodoParameters params;

    public FrodoKeyParameters(
        boolean isPrivate,
        FrodoParameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    public FrodoParameters getParameters()
    {
        return params;
    }

}
