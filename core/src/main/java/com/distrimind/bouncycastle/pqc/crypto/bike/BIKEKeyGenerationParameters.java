package com.distrimind.bouncycastle.pqc.crypto.bike;

import java.security.SecureRandom;

import com.distrimind.bouncycastle.crypto.KeyGenerationParameters;

public class BIKEKeyGenerationParameters
    extends KeyGenerationParameters
{
    private BIKEParameters params;

    public BIKEKeyGenerationParameters(
        SecureRandom random,
        BIKEParameters params)
    {
        super(random, 256);
        this.params = params;
    }

    public BIKEParameters getParameters()
    {
        return params;
    }
}
