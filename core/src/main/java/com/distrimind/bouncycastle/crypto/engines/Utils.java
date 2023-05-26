package com.distrimind.bouncycastle.crypto.engines;

import com.distrimind.bouncycastle.crypto.CryptoServicePurpose;

class Utils
{
    static CryptoServicePurpose getPurpose(boolean forEncryption)
    {
        return forEncryption ? CryptoServicePurpose.ENCRYPTION : CryptoServicePurpose.DECRYPTION;
    }
}
