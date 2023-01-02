package com.distrimind.bouncycastle.pqc.crypto.frodo;

import java.security.SecureRandom;

import com.distrimind.bouncycastle.crypto.EncapsulatedSecretGenerator;
import com.distrimind.bouncycastle.crypto.SecretWithEncapsulation;
import com.distrimind.bouncycastle.pqc.crypto.util.SecretWithEncapsulationImpl;
import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class FrodoKEMGenerator
    implements EncapsulatedSecretGenerator
{
    // the source of randomness
    private final SecureRandom sr;

    public FrodoKEMGenerator(SecureRandom random)
    {
        this.sr = random;
    }

    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey)
    {
        FrodoPublicKeyParameters key = (FrodoPublicKeyParameters)recipientKey;
        FrodoEngine engine = key.getParameters().getEngine();
        byte[] cipher_text = new byte[engine.getCipherTextSize()];
        byte[] sessionKey = new byte[engine.getSessionKeySize()];
        engine.kem_enc(cipher_text, sessionKey, key.getPublicKey(), sr);
        return new SecretWithEncapsulationImpl(sessionKey, cipher_text);
    }
}
