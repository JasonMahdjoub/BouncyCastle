package org.bouncycastle.bccrypto.generators;

import java.security.SecureRandom;

import org.bouncycastle.bccrypto.AsymmetricCipherKeyPair;
import org.bouncycastle.bccrypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.bccrypto.KeyGenerationParameters;
import org.bouncycastle.bccrypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.bccrypto.params.Ed25519PublicKeyParameters;

public class Ed25519KeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private SecureRandom random;

    public void init(KeyGenerationParameters parameters)
    {
        this.random = parameters.getRandom();
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        Ed25519PrivateKeyParameters privateKey = new Ed25519PrivateKeyParameters(random);
        Ed25519PublicKeyParameters publicKey = privateKey.generatePublicKey();
        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }
}
