package com.distrimind.bouncycastle.pqc.legacy.crypto.sike;

import java.security.SecureRandom;

import com.distrimind.bouncycastle.crypto.AsymmetricCipherKeyPair;
import com.distrimind.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import com.distrimind.bouncycastle.crypto.CryptoServicePurpose;
import com.distrimind.bouncycastle.crypto.CryptoServicesRegistrar;
import com.distrimind.bouncycastle.crypto.KeyGenerationParameters;
import com.distrimind.bouncycastle.crypto.constraints.DefaultServiceProperties;

public class SIKEKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private SIKEKeyGenerationParameters sikeParams;

    private SecureRandom random;

    private void initialize(KeyGenerationParameters param)
    {
        this.sikeParams = (SIKEKeyGenerationParameters) param;
        this.random = param.getRandom();
    }

    private AsymmetricCipherKeyPair genKeyPair()
    {
        // -DM System.err.println
        System.err.println("WARNING: the SIKE algorithm is only for research purposes, insecure");
        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties("SIKEKeyGen", 0, sikeParams.getParameters(), CryptoServicePurpose.KEYGEN));

        SIKEEngine engine = sikeParams.getParameters().getEngine();
        byte[] sk = new byte[engine.getPrivateKeySize()];
        byte[] pk = new byte[engine.getPublicKeySize()];

        engine.crypto_kem_keypair(pk, sk, random);


        SIKEPublicKeyParameters pubKey = new SIKEPublicKeyParameters(sikeParams.getParameters(), pk);
        SIKEPrivateKeyParameters privKey = new SIKEPrivateKeyParameters(sikeParams.getParameters(), sk);
        return new AsymmetricCipherKeyPair(pubKey, privKey);
    }

    public void init(KeyGenerationParameters param)
    {
        this.initialize(param);
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        return genKeyPair();
    }
}
