package org.bouncycastle.bccrypto.ec;

import org.bouncycastle.bccrypto.CipherParameters;
import org.bouncycastle.bcmath.ec.ECPoint;

public interface ECDecryptor
{
    void init(CipherParameters params);

    ECPoint decrypt(ECPair cipherText);
}
