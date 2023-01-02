package com.distrimind.bouncycastle.pqc.jcajce.provider.cmce;

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
import com.distrimind.bouncycastle.pqc.crypto.cmce.CMCEKEMExtractor;
import com.distrimind.bouncycastle.pqc.crypto.cmce.CMCEKEMGenerator;
import com.distrimind.bouncycastle.util.Arrays;

public class CMCEKeyGeneratorSpi
    extends KeyGeneratorSpi
{
    private KEMGenerateSpec genSpec;
    private SecureRandom random;
    private KEMExtractSpec extSpec;

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
        }
        else if (algorithmParameterSpec instanceof KEMExtractSpec)
        {
            this.genSpec = null;
            this.extSpec = (KEMExtractSpec)algorithmParameterSpec;
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
            BCCMCEPublicKey pubKey = (BCCMCEPublicKey)genSpec.getPublicKey();
            CMCEKEMGenerator kemGen = new CMCEKEMGenerator(random);

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
            BCCMCEPrivateKey privKey = (BCCMCEPrivateKey)extSpec.getPrivateKey();
            CMCEKEMExtractor kemExt = new CMCEKEMExtractor(privKey.getKeyParams());

            byte[] encapsulation = extSpec.getEncapsulation();
            byte[] secret = kemExt.extractSecret(encapsulation);

            SecretKey rv = new SecretKeyWithEncapsulation(new SecretKeySpec(secret, extSpec.getKeyAlgorithmName()), encapsulation);

            Arrays.clear(secret);

            return rv;
        }
    }
}
