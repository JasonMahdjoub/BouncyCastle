package com.distrimind.bouncycastle.openpgp.operator.jcajce;

import java.security.PrivateKey;

import com.distrimind.bouncycastle.openpgp.PGPPrivateKey;
import com.distrimind.bouncycastle.openpgp.PGPPublicKey;

/**
 * A JCA PrivateKey carrier. Use this one if you're dealing with a hardware adapter.
 */
public class JcaPGPPrivateKey
    extends PGPPrivateKey
{
    private final PrivateKey privateKey;

    public JcaPGPPrivateKey(long keyID, PrivateKey privateKey)
    {
        super(keyID, null, null);

        this.privateKey = privateKey;
    }

    public JcaPGPPrivateKey(PGPPublicKey pubKey, PrivateKey privateKey)
    {
        super(pubKey.getKeyID(), pubKey.getPublicKeyPacket(), null);

        this.privateKey = privateKey;
    }

    public PrivateKey getPrivateKey()
    {
        return privateKey;
    }
}
