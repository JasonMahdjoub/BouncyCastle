package org.bouncycastle.cms.bc;

import org.bouncycastle.bccrypto.CipherParameters;
import org.bouncycastle.bccrypto.params.KeyParameter;
import org.bouncycastle.operator.GenericKey;

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
