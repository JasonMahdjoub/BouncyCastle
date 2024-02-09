package com.distrimind.bouncycastle.its;

import com.distrimind.bouncycastle.oer.its.ieee1609dot2.EncryptedDataEncryptionKey;

public interface ETSIKeyWrapper
{
    EncryptedDataEncryptionKey wrap(byte[] secretKey);
}
