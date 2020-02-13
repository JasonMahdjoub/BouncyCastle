package org.bouncycastle.bccrypto.ec;

import org.bouncycastle.bccrypto.CipherParameters;

public interface ECPairTransform
{
    void init(CipherParameters params);

    ECPair transform(ECPair cipherText);
}
