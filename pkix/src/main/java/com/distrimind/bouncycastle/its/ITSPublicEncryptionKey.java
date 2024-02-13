package com.distrimind.bouncycastle.its;

import com.distrimind.bouncycastle.oer.its.ieee1609dot2.basetypes.PublicEncryptionKey;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.basetypes.SymmAlgorithm;

public class ITSPublicEncryptionKey
{
    protected final PublicEncryptionKey encryptionKey;

    public ITSPublicEncryptionKey(PublicEncryptionKey encryptionKey)
    {
        this.encryptionKey = encryptionKey;
    }

    public enum symmAlgorithm
    {
        aes128Ccm(SymmAlgorithm.aes128Ccm.intValueExact());

        private final int tagValue;

        symmAlgorithm(int tagValue)
        {
            this.tagValue = tagValue;
        }
    }

    public PublicEncryptionKey toASN1Structure()
    {
        return encryptionKey;
    }
}