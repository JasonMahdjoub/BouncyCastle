package com.distrimind.bouncycastle.crypto.generators;

import java.math.BigInteger;

import com.distrimind.bouncycastle.util.BigIntegers;

public class SM2KeyPairGenerator
    extends ECKeyPairGenerator
{
    public SM2KeyPairGenerator()
    {
        super("SM2KeyGen");
    }

    protected boolean isOutOfRangeD(BigInteger d, BigInteger n)
    {
        return d.compareTo(ONE) < 0 || (d.compareTo(n.subtract(BigIntegers.ONE)) >= 0);
    }
}
