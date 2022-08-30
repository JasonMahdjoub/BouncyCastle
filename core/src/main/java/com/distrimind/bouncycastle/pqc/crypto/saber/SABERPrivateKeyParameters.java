package com.distrimind.bouncycastle.pqc.crypto.saber;

import com.distrimind.bouncycastle.util.Arrays;

public class SABERPrivateKeyParameters
    extends SABERKeyParameters
{
    private byte[] privateKey;

    public byte[] getPrivateKey()
    {
        return Arrays.clone(privateKey);
    }

    public SABERPrivateKeyParameters(SABERParameters params, byte[] privateKey)
    {
        super(true, params);
        this.privateKey = Arrays.clone(privateKey);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(privateKey);
    }
}
