package com.distrimind.bouncycastle.pqc.crypto.sphincsplus;

import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class SPHINCSPlusKeyParameters
    extends AsymmetricKeyParameter
{
    final SPHINCSPlusParameters parameters;

    protected SPHINCSPlusKeyParameters(boolean isPrivate, SPHINCSPlusParameters parameters)
    {
        super(isPrivate);
        this.parameters = parameters;
    }

    public SPHINCSPlusParameters getParameters()
    {
        return parameters;
    }
}
