package org.bouncycastle.operator.bc;

import com.distrimind.bouncycastle.crypto.engines.AESWrapEngine;
import com.distrimind.bouncycastle.crypto.params.KeyParameter;

public class BcAESSymmetricKeyWrapper
    extends BcSymmetricKeyWrapper
{
    public BcAESSymmetricKeyWrapper(KeyParameter wrappingKey)
    {
        super(AESUtil.determineKeyEncAlg(wrappingKey), new AESWrapEngine(), wrappingKey);
    }
}
