package com.distrimind.bouncycastle.pqc.jcajce.provider.kyber;

import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;

import com.distrimind.bouncycastle.crypto.SecretWithEncapsulation;
import com.distrimind.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import com.distrimind.bouncycastle.jcajce.spec.KEMExtractSpec;
import com.distrimind.bouncycastle.jcajce.spec.KEMGenerateSpec;
import com.distrimind.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMExtractor;
import com.distrimind.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMGenerator;
import com.distrimind.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;
import com.distrimind.bouncycastle.util.Arrays;
import com.distrimind.bouncycastle.util.Strings;

public class KyberKeyGeneratorSpi
        extends KeyGeneratorSpi
{
    private KEMGenerateSpec genSpec;
    private SecureRandom random;
    private KEMExtractSpec extSpec;
    private KyberParameters kyberParameters;

    public KyberKeyGeneratorSpi()
    {
        this(null);
    }

    protected KyberKeyGeneratorSpi(KyberParameters kyberParameters)
    {
        this.kyberParameters = kyberParameters;
    }

    protected void engineInit(SecureRandom secureRandom)
    {
        throw new UnsupportedOperationException("Operation not supported");
    }

    protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom)
            throws InvalidAlgorithmParameterException
    {
        this.random = secureRandom;
        if (algorithmParameterSpec instanceof KEMGenerateSpec)
        {
            this.genSpec = (KEMGenerateSpec)algorithmParameterSpec;
            this.extSpec = null;
            if (kyberParameters != null)
            {
                String canonicalAlgName = Strings.toUpperCase(kyberParameters.getName());
                if (!canonicalAlgName.equals(genSpec.getPublicKey().getAlgorithm()))
                {
                    throw new InvalidAlgorithmParameterException("key generator locked to " + canonicalAlgName);
                }
            }
        }
        else if (algorithmParameterSpec instanceof KEMExtractSpec)
        {
            this.genSpec = null;
            this.extSpec = (KEMExtractSpec)algorithmParameterSpec;
            if (kyberParameters != null)
            {
                String canonicalAlgName = Strings.toUpperCase(kyberParameters.getName());
                if (!canonicalAlgName.equals(extSpec.getPrivateKey().getAlgorithm()))
                {
                    throw new InvalidAlgorithmParameterException("key generator locked to " + canonicalAlgName);
                }
            }
        }
        else
        {
            throw new InvalidAlgorithmParameterException("unknown spec");
        }
    }

    protected void engineInit(int i, SecureRandom secureRandom)
    {
        throw new UnsupportedOperationException("Operation not supported");
    }

    protected SecretKey engineGenerateKey()
    {
        if (genSpec != null)
        {
            BCKyberPublicKey pubKey = (BCKyberPublicKey)genSpec.getPublicKey();
            KyberKEMGenerator kemGen = new KyberKEMGenerator(random);

            SecretWithEncapsulation secEnc = kemGen.generateEncapsulated(pubKey.getKeyParams());

            SecretKey rv = new SecretKeyWithEncapsulation(new SecretKeySpec(secEnc.getSecret(), genSpec.getKeyAlgorithmName()), secEnc.getEncapsulation());

            try
            {
                secEnc.destroy();
            }
            catch (DestroyFailedException e)
            {
                throw new IllegalStateException("key cleanup failed");
            }

            return rv;
        }
        else
        {
            BCKyberPrivateKey privKey = (BCKyberPrivateKey)extSpec.getPrivateKey();
            KyberKEMExtractor kemExt = new KyberKEMExtractor(privKey.getKeyParams());

            byte[] encapsulation = extSpec.getEncapsulation();
            byte[] secret = kemExt.extractSecret(encapsulation);

            SecretKey rv = new SecretKeyWithEncapsulation(new SecretKeySpec(secret, extSpec.getKeyAlgorithmName()), encapsulation);

            Arrays.clear(secret);

            return rv;
        }
    }

    public static class Kyber512
        extends KyberKeyGeneratorSpi
    {
        public Kyber512()
        {
            super(KyberParameters.kyber512);
        }
    }

    public static class Kyber768
        extends KyberKeyGeneratorSpi
    {
        public Kyber768()
        {
            super(KyberParameters.kyber768);
        }
    }

    public static class Kyber1024
        extends KyberKeyGeneratorSpi
    {
        public Kyber1024()
        {
            super(KyberParameters.kyber1024);
        }
    }

    public static class Kyber512_AES
        extends KyberKeyGeneratorSpi
    {
        public Kyber512_AES()
        {
            super(KyberParameters.kyber512_aes);
        }
    }

    public static class Kyber768_AES
        extends KyberKeyGeneratorSpi
    {
        public Kyber768_AES()
        {
            super(KyberParameters.kyber768_aes);
        }
    }

    public static class Kyber1024_AES
        extends KyberKeyGeneratorSpi
    {
        public Kyber1024_AES()
        {
            super(KyberParameters.kyber1024_aes);
        }
    }
}
