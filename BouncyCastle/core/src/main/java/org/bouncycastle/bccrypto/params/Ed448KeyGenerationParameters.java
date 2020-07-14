package org.bouncycastle.bccrypto.params;

import java.security.SecureRandom;

import org.bouncycastle.bccrypto.KeyGenerationParameters;

public class Ed448KeyGenerationParameters
    extends KeyGenerationParameters
{
    public Ed448KeyGenerationParameters(SecureRandom random)
    {
        super(random, 448);
    }
}