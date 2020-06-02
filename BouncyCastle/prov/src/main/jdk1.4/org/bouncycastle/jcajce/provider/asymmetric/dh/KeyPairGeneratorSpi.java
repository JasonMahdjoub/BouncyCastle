package org.bouncycastle.bcjcajce.provider.asymmetric.dh;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Hashtable;

import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.bccrypto.AsymmetricCipherKeyPair;
import org.bouncycastle.bccrypto.CryptoServicesRegistrar;
import org.bouncycastle.bccrypto.generators.DHBasicKeyPairGenerator;
import org.bouncycastle.bccrypto.generators.DHParametersGenerator;
import org.bouncycastle.bccrypto.params.DHKeyGenerationParameters;
import org.bouncycastle.bccrypto.params.DHParameters;
import org.bouncycastle.bccrypto.params.DHPrivateKeyParameters;
import org.bouncycastle.bccrypto.params.DHPublicKeyParameters;
import org.bouncycastle.bcjcajce.provider.asymmetric.util.PrimeCertaintyCalculator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.bcutil.Integers;

public class KeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private static Hashtable params = new Hashtable();
    private static Object    lock = new Object();

    DHKeyGenerationParameters param;
    DHBasicKeyPairGenerator engine = new DHBasicKeyPairGenerator();
    int strength = 2048;
    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public KeyPairGeneratorSpi()
    {
        super("DH");
    }

    public void initialize(
        int strength,
        SecureRandom random)
    {
        this.strength = strength;
        this.random = random;
        this.initialised = false;
    }

    public void initialize(
        AlgorithmParameterSpec params,
        SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        if (!(params instanceof DHParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("parameter object not a DHParameterSpec");
        }
        DHParameterSpec dhParams = (DHParameterSpec)params;

        try
        {
            param = new DHKeyGenerationParameters(random, new DHParameters(dhParams.getP(), dhParams.getG(), null, dhParams.getL()));
        }
        catch (IllegalArgumentException e)
        {
            throw new InvalidAlgorithmParameterException(e.getMessage());
        }
        
        engine.init(param);
        initialised = true;
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            Integer paramStrength = Integers.valueOf(strength);

            if (params.containsKey(paramStrength))
            {
                param = (DHKeyGenerationParameters)params.get(paramStrength);
            }
            else
            {
                DHParameterSpec dhParams = BouncyCastleProvider.CONFIGURATION.getDHDefaultParameters(strength);

                if (dhParams != null)
                {
                    param = new DHKeyGenerationParameters(random, new DHParameters(dhParams.getP(), dhParams.getG(), null, dhParams.getL()));
                }
                else
                {
                    synchronized (lock)
                    {
                        // we do the check again in case we were blocked by a generator for
                        // our key size.
                        if (params.containsKey(paramStrength))
                        {
                            param = (DHKeyGenerationParameters)params.get(paramStrength);
                        }
                        else
                        {

                            DHParametersGenerator pGen = new DHParametersGenerator();

                            pGen.init(strength, PrimeCertaintyCalculator.getDefaultCertainty(strength), random);

                            param = new DHKeyGenerationParameters(random, pGen.generateParameters());

                            params.put(paramStrength, param);
                        }
                    }
                }
            }

            engine.init(param);

            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        DHPublicKeyParameters pub = (DHPublicKeyParameters)pair.getPublic();
        DHPrivateKeyParameters priv = (DHPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCDHPublicKey(pub), new BCDHPrivateKey(priv));
    }
}
