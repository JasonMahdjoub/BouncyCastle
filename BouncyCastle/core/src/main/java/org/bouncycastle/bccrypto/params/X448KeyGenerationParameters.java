package org.bouncycastle.bccrypto.params;

import java.security.SecureRandom;

import org.bouncycastle.bccrypto.KeyGenerationParameters;

public class X448KeyGenerationParameters
    extends KeyGenerationParameters
{
    public X448KeyGenerationParameters(SecureRandom random)
    {
        super(random, 448);
    }
}
