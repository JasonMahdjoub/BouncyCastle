package com.distrimind.bouncycastle.pqc.crypto.ntru;

import java.security.SecureRandom;

import com.distrimind.bouncycastle.pqc.math.ntru.parameters.NTRUParameterSet;
import com.distrimind.bouncycastle.crypto.AsymmetricCipherKeyPair;
import com.distrimind.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import com.distrimind.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Key generator for NTRU.
 * <p>
 * Note: the {@link #init(KeyGenerationParameters)} method only accepts {@link NTRUKeyParameters}. Otherwise, a
 * {@link ClassCastException} may occur.
 */
public class NTRUKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private NTRUKeyGenerationParameters params;
    private SecureRandom random;

    @Override
    public void init(KeyGenerationParameters param)
    {
        this.params = (NTRUKeyGenerationParameters)param;
        this.random = param.getRandom();
    }

    @Override
    public AsymmetricCipherKeyPair generateKeyPair()
    {
//        assert this.random != null;
        NTRUParameterSet parameterSet = this.params.getParameters().parameterSet;
        byte[] seed = new byte[parameterSet.sampleFgBytes()];
        random.nextBytes(seed);

        NTRUOWCPA owcpa = new NTRUOWCPA(parameterSet);
        OWCPAKeyPair owcpaKeys = owcpa.keypair(seed);
        byte[] publicKey = owcpaKeys.publicKey;
        byte[] privateKey = new byte[parameterSet.ntruSecretKeyBytes()];
        byte[] owcpaPrivateKey = owcpaKeys.privateKey;
        System.arraycopy(owcpaPrivateKey, 0, privateKey, 0, owcpaPrivateKey.length);

        byte[] prfBytes = new byte[parameterSet.prfKeyBytes()];
        random.nextBytes(prfBytes);
        System.arraycopy(prfBytes, 0, privateKey, parameterSet.owcpaSecretKeyBytes(), prfBytes.length);

        return new AsymmetricCipherKeyPair(new NTRUPublicKeyParameters(params.getParameters(), publicKey), new NTRUPrivateKeyParameters(params.getParameters(), privateKey));
    }
}
