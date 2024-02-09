package com.distrimind.bouncycastle.crypto.prng;

public interface EntropySourceProvider
{
    EntropySource get(final int bitsRequired);
}
