package com.distrimind.bouncycastle.operator.bc;

import com.distrimind.bouncycastle.crypto.engines.AESWrapEngine;
import com.distrimind.bouncycastle.crypto.params.KeyParameter;

public class BcAESSymmetricKeyUnwrapper
    extends BcSymmetricKeyUnwrapper
{
    public BcAESSymmetricKeyUnwrapper(KeyParameter wrappingKey)
    {
        super(AESUtil.determineKeyEncAlg(wrappingKey), new AESWrapEngine(), wrappingKey);
    }
}
