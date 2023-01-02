package com.distrimind.bouncycastle.pqc.crypto.bike;

import com.distrimind.bouncycastle.util.Arrays;

public class BIKEPublicKeyParameters
    extends BIKEKeyParameters
{
    byte[] publicKey;

    /**
     * Constructor.
     *
     * @param publicKey byte
     */
    public BIKEPublicKeyParameters(BIKEParameters params, byte[] publicKey)
    {
        super(false, params);
        this.publicKey = Arrays.clone(publicKey);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(publicKey);
    }
}
