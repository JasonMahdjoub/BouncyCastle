package org.bouncycastle.bccrypto.prng;

public interface EntropySourceProvider
{
    EntropySource get(final int bitsRequired);
}
