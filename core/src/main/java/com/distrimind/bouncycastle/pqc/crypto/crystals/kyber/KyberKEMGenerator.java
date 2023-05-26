package com.distrimind.bouncycastle.pqc.crypto.crystals.kyber;

import java.security.SecureRandom;

import com.distrimind.bouncycastle.crypto.EncapsulatedSecretGenerator;
import com.distrimind.bouncycastle.crypto.SecretWithEncapsulation;
import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;
import com.distrimind.bouncycastle.pqc.crypto.util.SecretWithEncapsulationImpl;

public class KyberKEMGenerator
    implements EncapsulatedSecretGenerator
{
    // the source of randomness
    private final SecureRandom sr;

    public KyberKEMGenerator(SecureRandom random)
    {
        this.sr = random;
    }

    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey)
    {
        KyberPublicKeyParameters key = (KyberPublicKeyParameters)recipientKey;
        KyberEngine engine = key.getParameters().getEngine();
        engine.init(sr);
        byte[][] kemEncrypt = engine.kemEncrypt(key.getPublicKey());
        return new SecretWithEncapsulationImpl(kemEncrypt[0], kemEncrypt[1]);
    }
}
