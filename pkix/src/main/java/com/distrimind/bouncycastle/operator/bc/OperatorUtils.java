package com.distrimind.bouncycastle.operator.bc;

import java.security.Key;

import com.distrimind.bouncycastle.operator.GenericKey;

class OperatorUtils
{
    static byte[] getKeyBytes(GenericKey key)
    {
        if (key.getRepresentation() instanceof Key)
        {
            return ((Key)key.getRepresentation()).getEncoded();
        }

        if (key.getRepresentation() instanceof byte[])
        {
            return (byte[])key.getRepresentation();
        }

        throw new IllegalArgumentException("unknown generic key type");
    }
}