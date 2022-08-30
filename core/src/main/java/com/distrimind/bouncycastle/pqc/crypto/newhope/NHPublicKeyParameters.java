package com.distrimind.bouncycastle.pqc.crypto.newhope;

import com.distrimind.bouncycastle.util.Arrays;
import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class NHPublicKeyParameters
    extends AsymmetricKeyParameter
{
    final byte[] pubData;

    public NHPublicKeyParameters(byte[] pubData)
    {
        super(false);
        this.pubData = Arrays.clone(pubData);
    }

    /**
     * Return the public key data.
     *
     * @return the public key values.
     */
    public byte[] getPubData()
    {
        return Arrays.clone(pubData);
    }
}
