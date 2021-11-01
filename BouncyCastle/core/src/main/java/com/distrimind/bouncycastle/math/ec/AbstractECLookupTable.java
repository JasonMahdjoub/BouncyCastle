package com.distrimind.bouncycastle.math.ec;

public abstract class AbstractECLookupTable
    implements ECLookupTable
{
    public ECPoint lookupVar(int index)
    {
        return lookup(index);
    }
}
