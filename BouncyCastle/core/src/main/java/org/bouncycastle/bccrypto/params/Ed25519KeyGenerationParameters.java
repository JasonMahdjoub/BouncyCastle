package org.bouncycastle.bccrypto.params;

import java.security.SecureRandom;

import org.bouncycastle.bccrypto.KeyGenerationParameters;

public class Ed25519KeyGenerationParameters
    extends KeyGenerationParameters
{
    public Ed25519KeyGenerationParameters(SecureRandom random)
    {
        super(random, 256);
    }
}
