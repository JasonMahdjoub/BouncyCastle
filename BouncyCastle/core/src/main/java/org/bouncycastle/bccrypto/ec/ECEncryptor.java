package org.bouncycastle.bccrypto.ec;

import org.bouncycastle.bccrypto.CipherParameters;
import org.bouncycastle.bcmath.ec.ECPoint;

public interface ECEncryptor
{
    void init(CipherParameters params);

    ECPair encrypt(ECPoint point);
}
