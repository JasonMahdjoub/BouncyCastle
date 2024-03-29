package com.distrimind.bouncycastle.pqc.crypto.cmce;

import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class CMCEKeyParameters
    extends AsymmetricKeyParameter
{
    private CMCEParameters params;

    public CMCEKeyParameters(
        boolean isPrivate,
        CMCEParameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    public CMCEParameters getParameters()
    {
        return params;
    }

}
