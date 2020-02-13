package org.bouncycastle.bccrypto.params;

import java.security.SecureRandom;

import org.bouncycastle.bccrypto.CipherParameters;
import org.bouncycastle.bccrypto.BCCryptoServicesRegistrar;

public class ParametersWithRandom
    implements CipherParameters
{
    private SecureRandom        random;
    private CipherParameters parameters;

    public ParametersWithRandom(
        CipherParameters parameters,
        SecureRandom        random)
    {
        this.random = random;
        this.parameters = parameters;
    }

    public ParametersWithRandom(
        CipherParameters parameters)
    {
        this(parameters, BCCryptoServicesRegistrar.getSecureRandom());
    }

    public SecureRandom getRandom()
    {
        return random;
    }

    public CipherParameters getParameters()
    {
        return parameters;
    }
}
