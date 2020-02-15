package org.bouncycastle.bcjcajce.provider.symmetric.util;

import org.bouncycastle.bccrypto.BlockCipher;

public interface BlockCipherProvider
{
    BlockCipher get();
}
