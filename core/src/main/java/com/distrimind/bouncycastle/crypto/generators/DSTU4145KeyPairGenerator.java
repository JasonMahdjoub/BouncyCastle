package com.distrimind.bouncycastle.crypto.generators;

import com.distrimind.bouncycastle.crypto.AsymmetricCipherKeyPair;
import com.distrimind.bouncycastle.crypto.params.ECPrivateKeyParameters;
import com.distrimind.bouncycastle.crypto.params.ECPublicKeyParameters;

public class DSTU4145KeyPairGenerator
    extends ECKeyPairGenerator
{
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        AsymmetricCipherKeyPair pair = super.generateKeyPair();

        ECPublicKeyParameters pub = (ECPublicKeyParameters)pair.getPublic();
        ECPrivateKeyParameters priv = (ECPrivateKeyParameters)pair.getPrivate();

        pub = new ECPublicKeyParameters(pub.getQ().negate(), pub.getParameters());

        return new AsymmetricCipherKeyPair(pub, priv);
    }
}
