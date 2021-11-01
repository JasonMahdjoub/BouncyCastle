package com.distrimind.bouncycastle.tls.crypto.impl.bc;

import com.distrimind.bouncycastle.crypto.prng.RandomGenerator;
import com.distrimind.bouncycastle.tls.crypto.TlsNonceGenerator;

final class BcTlsNonceGenerator
    implements TlsNonceGenerator
{
    private final RandomGenerator randomGenerator;

    BcTlsNonceGenerator(RandomGenerator randomGenerator)
    {
        this.randomGenerator = randomGenerator;
    }

    public byte[] generateNonce(int size)
    {
        byte[] nonce = new byte[size];
        randomGenerator.nextBytes(nonce);
        return nonce;
    }
}
