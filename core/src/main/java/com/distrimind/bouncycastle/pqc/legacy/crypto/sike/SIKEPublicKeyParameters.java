package com.distrimind.bouncycastle.pqc.legacy.crypto.sike;

import com.distrimind.bouncycastle.util.Arrays;

public class SIKEPublicKeyParameters
    extends SIKEKeyParameters
{
    private final byte[] publicKey;

    public byte[] getPublicKey()
    {
        return Arrays.clone(publicKey);
    }

    public byte[] getEncoded()
    {
        return getPublicKey();
    }

    public SIKEPublicKeyParameters(SIKEParameters params, byte[] publicKey)
    {
        super(false, params);
        this.publicKey = Arrays.clone(publicKey);
    }
}
