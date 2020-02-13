package org.bouncycastle.pqc.jcajce.provider.rainbow;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.bccrypto.AsymmetricCipherKeyPair;
import org.bouncycastle.bccrypto.BCCryptoServicesRegistrar;
import org.bouncycastle.pqc.crypto.rainbow.*;
import org.bouncycastle.pqc.crypto.rainbow.RainbowParameters;
import org.bouncycastle.pqc.jcajce.spec.RainbowParameterSpec;

public class RainbowKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    RainbowKeyGenerationParameters param;
    RainbowKeyPairGenerator engine = new RainbowKeyPairGenerator();
    int strength = 1024;
    SecureRandom random = BCCryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public RainbowKeyPairGeneratorSpi()
    {
        super("Rainbow");
    }

    public void initialize(
        int strength,
        SecureRandom random)
    {
        this.strength = strength;
        this.random = random;
    }

    public void initialize(
        AlgorithmParameterSpec params,
        SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        if (!(params instanceof RainbowParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("parameter object not a RainbowParameterSpec");
        }
        RainbowParameterSpec rainbowParams = (RainbowParameterSpec)params;

        param = new RainbowKeyGenerationParameters(random, new RainbowParameters(rainbowParams.getVi()));

        engine.init(param);
        initialised = true;
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            param = new RainbowKeyGenerationParameters(random, new RainbowParameters(new RainbowParameterSpec().getVi()));

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        RainbowPublicKeyParameters pub = (RainbowPublicKeyParameters)pair.getPublic();
        RainbowPrivateKeyParameters priv = (RainbowPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCRainbowPublicKey(pub),
            new BCRainbowPrivateKey(priv));
    }
}
