package org.bouncycastle.bccrypto.prng;

import org.bouncycastle.bccrypto.prng.drbg.SP80090DRBG;

interface DRBGProvider
{
    SP80090DRBG get(EntropySource entropySource);
}
