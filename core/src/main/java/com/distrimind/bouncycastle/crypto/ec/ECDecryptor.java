package com.distrimind.bouncycastle.crypto.ec;

import com.distrimind.bouncycastle.crypto.CipherParameters;
import com.distrimind.bouncycastle.math.ec.ECPoint;

public interface ECDecryptor
{
    void init(CipherParameters params);

    ECPoint decrypt(ECPair cipherText);
}
