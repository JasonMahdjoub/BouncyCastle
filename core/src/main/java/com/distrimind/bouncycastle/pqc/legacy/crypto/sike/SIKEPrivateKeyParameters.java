package com.distrimind.bouncycastle.pqc.legacy.crypto.sike;

import com.distrimind.bouncycastle.util.Arrays;

public class SIKEPrivateKeyParameters
    extends SIKEKeyParameters
{
    private byte[] privateKey;

    public byte[] getPrivateKey()
    {
        return Arrays.clone(privateKey);
    }

    public SIKEPrivateKeyParameters(SIKEParameters params, byte[] privateKey)
    {
        super(true, params);
        this.privateKey = Arrays.clone(privateKey);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(privateKey);
    }
}
