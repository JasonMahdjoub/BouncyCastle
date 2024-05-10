package com.distrimind.bouncycastle.pqc.crypto.xwing;

import java.security.SecureRandom;

import com.distrimind.bouncycastle.crypto.KeyGenerationParameters;

public class XWingKeyGenerationParameters
    extends KeyGenerationParameters
{
    public XWingKeyGenerationParameters(SecureRandom random)
    {
        super(random, 128);
    }
}
