package com.distrimind.bouncycastle.operator.bc;

import com.distrimind.bouncycastle.operator.GenericKey;

class OperatorUtils
{
    static byte[] getKeyBytes(GenericKey key)
    {
        if (key.getRepresentation() instanceof byte[])
        {
            return (byte[])key.getRepresentation();
        }

        throw new IllegalArgumentException("unknown generic key type");
    }
}
