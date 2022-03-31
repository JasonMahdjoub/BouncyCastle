package com.distrimind.bouncycastle.cms.bc;

import com.distrimind.bouncycastle.crypto.CipherParameters;
import com.distrimind.bouncycastle.crypto.params.KeyParameter;
import com.distrimind.bouncycastle.operator.GenericKey;

class CMSUtils
{
    static CipherParameters getBcKey(GenericKey key)
    {
        if (key.getRepresentation() instanceof CipherParameters)
        {
            return (CipherParameters)key.getRepresentation();
        }

        if (key.getRepresentation() instanceof byte[])
        {
            return new KeyParameter((byte[])key.getRepresentation());
        }

        throw new IllegalArgumentException("unknown generic key type");
    }
}
