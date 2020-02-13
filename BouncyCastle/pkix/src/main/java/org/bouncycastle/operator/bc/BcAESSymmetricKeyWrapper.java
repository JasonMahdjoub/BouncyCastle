package org.bouncycastle.operator.bc;

import org.bouncycastle.bccrypto.engines.AESWrapEngine;
import org.bouncycastle.bccrypto.params.KeyParameter;

public class BcAESSymmetricKeyWrapper
    extends BcSymmetricKeyWrapper
{
    public BcAESSymmetricKeyWrapper(KeyParameter wrappingKey)
    {
        super(AESUtil.determineKeyEncAlg(wrappingKey), new AESWrapEngine(), wrappingKey);
    }
}
