package org.bouncycastle.jcajce.provider.symmetric.util;

import org.bouncycastle.bccrypto.BlockCipher;

public interface BlockCipherProvider
{
    BlockCipher get();
}
