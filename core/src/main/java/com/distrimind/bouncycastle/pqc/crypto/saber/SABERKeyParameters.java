package com.distrimind.bouncycastle.pqc.crypto.saber;

import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class SABERKeyParameters
    extends AsymmetricKeyParameter
{
    private SABERParameters params;
    public SABERKeyParameters(
            boolean isPrivate,
            SABERParameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    public SABERParameters getParameters()
    {
        return params;
    }
}
