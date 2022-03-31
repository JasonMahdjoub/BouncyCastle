package com.distrimind.bouncycastle.crypto.ec;

import com.distrimind.bouncycastle.crypto.CipherParameters;

public interface ECPairTransform
{
    void init(CipherParameters params);

    ECPair transform(ECPair cipherText);
}
