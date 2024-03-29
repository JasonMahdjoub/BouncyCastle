package com.distrimind.bouncycastle.pqc.crypto.hqc;

import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class HQCKeyParameters
    extends AsymmetricKeyParameter
{
    private HQCParameters params;

    public HQCKeyParameters(
        boolean isPrivate,
        HQCParameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    public HQCParameters getParameters()
    {
        return params;
    }
}
