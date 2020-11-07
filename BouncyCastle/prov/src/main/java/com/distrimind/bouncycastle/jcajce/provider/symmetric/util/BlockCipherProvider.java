package com.distrimind.bouncycastle.jcajce.provider.symmetric.util;

import com.distrimind.bouncycastle.crypto.BlockCipher;

public interface BlockCipherProvider
{
    BlockCipher get();
}
