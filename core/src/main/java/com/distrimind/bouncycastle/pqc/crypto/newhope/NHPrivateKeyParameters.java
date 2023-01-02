package com.distrimind.bouncycastle.pqc.crypto.newhope;

import com.distrimind.bouncycastle.util.Arrays;
import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class NHPrivateKeyParameters
    extends AsymmetricKeyParameter
{
    final short[] secData;

    public NHPrivateKeyParameters(short[] secData)
    {
        super(true);

        this.secData = Arrays.clone(secData);
    }

    public short[] getSecData()
    {
        return Arrays.clone(secData);
    }
}
