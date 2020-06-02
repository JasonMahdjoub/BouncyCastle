package org.bouncycastle.pqc.crypto.lms;

import org.bouncycastle.bccrypto.AsymmetricCipherKeyPair;
import org.bouncycastle.bccrypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.bccrypto.KeyGenerationParameters;

public class HSSKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    HSSKeyGenerationParameters param;

    public void init(KeyGenerationParameters param)
    {
        this.param = (HSSKeyGenerationParameters)param;
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        HSSPrivateKeyParameters privKey = HSS.generateHSSKeyPair(param);

        return new AsymmetricCipherKeyPair(privKey.getPublicKey(), privKey);
    }
}
