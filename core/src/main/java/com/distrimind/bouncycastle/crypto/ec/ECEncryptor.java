package com.distrimind.bouncycastle.crypto.ec;

import com.distrimind.bouncycastle.crypto.CipherParameters;
import com.distrimind.bouncycastle.math.ec.ECPoint;

public interface ECEncryptor
{
    void init(CipherParameters params);

    ECPair encrypt(ECPoint point);
}
